const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;

/* ================================
   SETTINGS
================================ */

const SMTP_USER =
  (process.env.SMTP_USER || "").trim();

const SMTP_PASS =
  (process.env.SMTP_PASS || "")
    .replace(/\s/g, "");

const OTP_EXPIRY =
  5 * 60 * 1000;

const RESEND_COOLDOWN =
  30 * 1000;

const MAX_ATTEMPTS = 5;

const RATE_WINDOW =
  60 * 1000;

const MAX_REQUESTS =
  10;


/* ================================
   MIDDLEWARE
================================ */

app.use(
  express.json({
    limit: "10kb"
  })
);

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"]
  })
);


/* ================================
   STORAGE
================================ */

const otpStore = new Map();
const ipStore = new Map();


/* ================================
   GMAIL SMTP
================================ */

const transporter =
  nodemailer.createTransport({

    host: "smtp.gmail.com",

    port: 465,

    secure: true,

    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    },

    connectionTimeout: 15000,

    greetingTimeout: 15000,

    socketTimeout: 20000

  });


/* ================================
   HELPERS
================================ */

function normalizeEmail(email) {

  return String(email || "")
    .trim()
    .toLowerCase();

}


function validEmail(email) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

}


function generateOTP() {

  return crypto
    .randomInt(1000, 10000)
    .toString();

}


function hashOTP(otp) {

  return crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");

}


function getIP(req) {

  const forwarded =
    req.headers["x-forwarded-for"];

  if (forwarded) {

    return forwarded
      .split(",")[0]
      .trim();

  }

  return req.socket.remoteAddress || "unknown";

}


/* ================================
   RATE LIMIT
================================ */

function allowedRequest(req) {

  const ip = getIP(req);

  const now = Date.now();

  let record = ipStore.get(ip);

  if (
    !record ||
    now - record.start > RATE_WINDOW
  ) {

    record = {
      start: now,
      count: 0
    };

    ipStore.set(ip, record);

  }

  record.count++;

  return record.count <= MAX_REQUESTS;

}


/* ================================
   ROOT
================================ */

app.get("/", (req, res) => {

  res.json({

    status: "online",

    gateway: "hrrymodsonline",

    service: "Email OTP Gateway"

  });

});


/* ================================
   HEALTH / SMTP CHECK
================================ */

app.get("/health", async (req, res) => {

  try {

    if (!SMTP_USER || !SMTP_PASS) {

      return res.status(500).json({

        ok: false,

        smtpConfigured: false,

        message:
          "SMTP_USER or SMTP_PASS is missing in Render Environment Variables."

      });

    }

    await transporter.verify();

    return res.json({

      ok: true,

      smtpConfigured: true,

      smtpConnected: true,

      message:
        "Gmail SMTP connection is working."

    });

  } catch (error) {

    console.error(
      "SMTP HEALTH ERROR:",
      error
    );

    return res.status(500).json({

      ok: false,

      smtpConfigured: true,

      smtpConnected: false,

      errorCode:
        error.code || "UNKNOWN",

      message:
        "Gmail SMTP connection failed. Check the Gmail App Password and Render Environment Variables."

    });

  }

});


/* ================================
   SEND OTP
================================ */

app.post(
  "/api/send-otp",
  async (req, res) => {

    try {

      if (!allowedRequest(req)) {

        return res.status(429).json({

          success: false,

          message:
            "Too many requests. Please try again later."

        });

      }


      const email =
        normalizeEmail(
          req.body.email
        );


      if (!validEmail(email)) {

        return res.status(400).json({

          success: false,

          message:
            "Please enter a valid email address."

        });

      }


      /* Check resend cooldown */

      const old =
        otpStore.get(email);


      if (old) {

        const elapsed =
          Date.now() -
          old.createdAt;

        if (
          elapsed <
          RESEND_COOLDOWN
        ) {

          const wait =
            Math.ceil(
              (
                RESEND_COOLDOWN -
                elapsed
              ) / 1000
            );

          return res.status(429).json({

            success: false,

            message:
              `Please wait ${wait} seconds before requesting another OTP.`

          });

        }

      }


      /* Check Gmail configuration */

      if (!SMTP_USER || !SMTP_PASS) {

        return res.status(500).json({

          success: false,

          message:
            "Gmail SMTP is not configured in Render. Add SMTP_USER and SMTP_PASS."

        });

      }


      /* Test SMTP before generating OTP */

      try {

        await transporter.verify();

      } catch (smtpError) {

        console.error(
          "GMAIL SMTP ERROR:",
          smtpError
        );

        return res.status(500).json({

          success: false,

          message:
            "Gmail authentication failed. Please create a new Gmail App Password and update SMTP_PASS in Render."

        });

      }


      /* Generate OTP */

      const otp =
        generateOTP();


      /* Save hashed OTP */

      otpStore.set(
        email,
        {

          otpHash:
            hashOTP(otp),

          createdAt:
            Date.now(),

          expiresAt:
            Date.now() +
            OTP_EXPIRY,

          attempts: 0

        }
      );


      /* Send email */

      try {

        await transporter.sendMail({

          from:
            `"hrrymodsonline" <${SMTP_USER}>`,

          to: email,

          subject:
            "Your hrrymodsonline OTP",

          text:
`Your hrrymodsonline verification OTP is: ${otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.`,

          html: `

<!DOCTYPE html>

<html>

<body
style="
margin:0;
padding:20px;
background:#f3f3f3;
font-family:Arial,sans-serif;
"
>

<div
style="
max-width:500px;
margin:auto;
background:white;
border-radius:18px;
padding:30px;
text-align:center;
"
>

<h2 style="color:#111;">
hrrymodsonline
</h2>

<p style="color:#555;">
Your email verification OTP is:
</p>

<div
style="
font-size:38px;
font-weight:bold;
letter-spacing:12px;
padding:20px;
background:#f5f5f5;
border-radius:14px;
color:#111;
margin:20px 0;
"
>

${otp}

</div>

<p style="color:#777;">
This OTP expires in 5 minutes.
</p>

<p style="font-size:12px;color:#999;">
Do not share this OTP with anyone.
</p>

</div>

</body>

</html>

`

        });

      } catch (mailError) {

        console.error(
          "MAIL SEND ERROR:",
          mailError
        );

        otpStore.delete(email);

        return res.status(500).json({

          success: false,

          message:
            "Gmail accepted the connection but failed to send the email. Please check the Gmail account/App Password."

        });

      }


      return res.json({

        success: true,

        message:
          "OTP sent successfully."

      });


    } catch (error) {

      console.error(
        "SEND OTP ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "OTP server error. Please check Render logs."

      });

    }

  }
);


/* ================================
   VERIFY OTP
================================ */

app.post(
  "/api/verify-otp",
  (req, res) => {

    try {

      if (!allowedRequest(req)) {

        return res.status(429).json({

          success: false,

          message:
            "Too many requests. Please try again later."

        });

      }


      const email =
        normalizeEmail(
          req.body.email
        );

      const otp =
        String(
          req.body.otp || ""
        ).trim();


      if (!validEmail(email)) {

        return res.status(400).json({

          success: false,

          message:
            "Invalid email address."

        });

      }


      if (!/^\d{4}$/.test(otp)) {

        return res.status(400).json({

          success: false,

          message:
            "OTP must contain exactly 4 digits."

        });

      }


      const record =
        otpStore.get(email);


      if (!record) {

        return res.status(400).json({

          success: false,

          message:
            "OTP not found. Please request a new OTP."

        });

      }


      /* Expired */

      if (
        Date.now() >
        record.expiresAt
      ) {

        otpStore.delete(email);

        return res.status(400).json({

          success: false,

          message:
            "OTP has expired. Please request a new OTP."

        });

      }


      /* Attempts */

      record.attempts++;


      if (
        record.attempts >
        MAX_ATTEMPTS
      ) {

        otpStore.delete(email);

        return res.status(429).json({

          success: false,

          message:
            "Too many incorrect attempts. Please request a new OTP."

        });

      }


      /* Compare */

      const enteredHash =
        hashOTP(otp);

      const savedHash =
        record.otpHash;


      const valid =
        enteredHash.length ===
        savedHash.length &&
        crypto.timingSafeEqual(
          Buffer.from(enteredHash),
          Buffer.from(savedHash)
        );


      if (!valid) {

        return res.status(400).json({

          success: false,

          message:
            "Incorrect OTP."

        });

      }


      /* One-time use */

      otpStore.delete(email);


      return res.json({

        success: true,

        verified: true,

        message:
          "Email verified successfully."

      });


    } catch (error) {

      console.error(
        "VERIFY ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Verification failed."

      });

    }

  }
);


/* ================================
   UNKNOWN API
================================ */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({

      success: false,

      message:
        "API endpoint not found."

    });

  }
);


/* ================================
   CLEANUP
================================ */

setInterval(
  () => {

    const now = Date.now();


    for (
      const [
        email,
        record
      ]
      of otpStore.entries()
    ) {

      if (
        now >
        record.expiresAt
      ) {

        otpStore.delete(email);

      }

    }


    for (
      const [
        ip,
        record
      ]
      of ipStore.entries()
    ) {

      if (
        now - record.start >
        RATE_WINDOW
      ) {

        ipStore.delete(ip);

      }

    }

  },

  60 * 1000
);


/* ================================
   START
================================ */

app.listen(
  PORT,
  () => {

    console.log(
      "================================"
    );

    console.log(
      "hrrymodsonline OTP Gateway"
    );

    console.log(
      "Port:",
      PORT
    );

    console.log(
      "SMTP User:",
      SMTP_USER || "NOT SET"
    );

    console.log(
      "SMTP Password:",
      SMTP_PASS
        ? "SET"
        : "NOT SET"
    );

    console.log(
      "================================"
    );

  }
);
