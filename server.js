const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;

/* =================================
   BREVO CONFIG
================================= */

const BREVO_API_KEY =
  (process.env.BREVO_API_KEY || "").trim();

const BREVO_SENDER_EMAIL =
  (process.env.BREVO_SENDER_EMAIL || "").trim();

const BREVO_SENDER_NAME =
  (process.env.BREVO_SENDER_NAME || "hrrymodsonline").trim();


/* =================================
   OTP CONFIG
================================= */

const OTP_EXPIRY = 5 * 60 * 1000;

const RESEND_COOLDOWN = 30 * 1000;

const MAX_ATTEMPTS = 5;

const RATE_WINDOW = 60 * 1000;

const MAX_REQUESTS = 10;


/* =================================
   MIDDLEWARE
================================= */

app.use(
  express.json({
    limit: "10kb"
  })
);

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Accept"
    ]
  })
);


/* =================================
   STORAGE
================================= */

const otpStore = new Map();

const ipStore = new Map();


/* =================================
   HELPERS
================================= */

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


/* =================================
   BREVO CONFIG CHECK
================================= */

function brevoConfigured() {

  return Boolean(
    BREVO_API_KEY &&
    BREVO_SENDER_EMAIL
  );
}


/* =================================
   SEND EMAIL THROUGH BREVO API
================================= */

async function sendBrevoOTP(email, otp) {

  const htmlContent = `

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1.0">

</head>

<body
style="
margin:0;
padding:25px 15px;
background:#f3f4f6;
font-family:Arial,Helvetica,sans-serif;
"
>

<div
style="
max-width:500px;
margin:0 auto;
background:#ffffff;
border-radius:20px;
padding:30px 20px;
text-align:center;
box-shadow:0 5px 25px rgba(0,0,0,0.08);
"
>

<h2
style="
margin:0 0 10px;
color:#111111;
font-size:24px;
"
>
hrrymodsonline
</h2>

<p
style="
margin:0;
color:#666666;
font-size:15px;
"
>
Your email verification OTP is
</p>

<div
style="
margin:25px 0;
padding:18px;
background:#f5f5f5;
border-radius:15px;
font-size:38px;
font-weight:800;
letter-spacing:12px;
color:#111111;
"
>
${otp}
</div>

<p
style="
margin:0;
color:#666666;
font-size:14px;
"
>
This OTP will expire in 5 minutes.
</p>

<p
style="
margin-top:20px;
font-size:12px;
color:#999999;
"
>
Do not share this OTP with anyone.
</p>

</div>

</body>

</html>

`;


  const response = await fetch(
    "https://api.brevo.com/v3/smtp/email",
    {

      method: "POST",

      headers: {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
      },

      body: JSON.stringify({

        sender: {
          name: BREVO_SENDER_NAME,
          email: BREVO_SENDER_EMAIL
        },

        to: [
          {
            email: email
          }
        ],

        subject:
          "Your hrrymodsonline OTP",

        htmlContent: htmlContent

      })

    }
  );


  const data =
    await response.json()
      .catch(() => ({}));


  if (!response.ok) {

    console.error(
      "BREVO ERROR:",
      response.status,
      data
    );

    const error =
      new Error(
        data.message ||
        "Brevo email sending failed."
      );

    error.status =
      response.status;

    throw error;
  }


  return data;
}


/* =================================
   ROOT
================================= */

app.get("/", (req, res) => {

  res.json({

    status: "online",

    gateway:
      "hrrymodsonline",

    service:
      "Brevo API OTP Gateway",

    sender:
      BREVO_SENDER_EMAIL ||
      "NOT SET"

  });

});


/* =================================
   HEALTH
================================= */

app.get(
  "/health",
  async (req, res) => {

    if (!brevoConfigured()) {

      return res.status(500).json({

        ok: false,

        brevoConfigured: false,

        message:
          "Brevo Environment Variables are missing."

      });

    }


    return res.json({

      ok: true,

      brevoConfigured: true,

      sender:
        BREVO_SENDER_EMAIL,

      message:
        "Brevo API configuration is ready."

    });

  }
);


/* =================================
   SEND OTP
================================= */

app.post(
  "/api/send-otp",
  async (req, res) => {

    try {

      /* =========================
         RATE LIMIT
      ========================= */

      if (!allowedRequest(req)) {

        return res.status(429).json({

          success: false,

          message:
            "Too many requests. Please try again later."

        });

      }


      /* =========================
         EMAIL
      ========================= */

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


      /* =========================
         BREVO CHECK
      ========================= */

      if (!brevoConfigured()) {

        return res.status(500).json({

          success: false,

          message:
            "Brevo API is not configured in Render."

        });

      }


      /* =========================
         RESEND COOLDOWN
      ========================= */

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


      /* =========================
         GENERATE OTP
      ========================= */

      const otp =
        generateOTP();


      /* =========================
         SEND EMAIL
      ========================= */

      try {

        await sendBrevoOTP(
          email,
          otp
        );

      } catch (mailError) {

        console.error(
          "BREVO SEND ERROR:",
          mailError
        );


        return res.status(500).json({

          success: false,

          message:
            "Unable to send OTP through email service. Please try again later."

        });

      }


      /* =========================
         SAVE OTP
      ========================= */

      const now =
        Date.now();


      otpStore.set(
        email,
        {

          otpHash:
            hashOTP(otp),

          createdAt:
            now,

          expiresAt:
            now +
            OTP_EXPIRY,

          attempts: 0

        }
      );


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


/* =================================
   VERIFY OTP
================================= */

app.post(
  "/api/verify-otp",
  (req, res) => {

    try {

      /* =========================
         RATE LIMIT
      ========================= */

      if (!allowedRequest(req)) {

        return res.status(429).json({

          success: false,

          message:
            "Too many requests. Please try again later."

        });

      }


      /* =========================
         INPUT
      ========================= */

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


      /* =========================
         FIND OTP
      ========================= */

      const record =
        otpStore.get(email);


      if (!record) {

        return res.status(400).json({

          success: false,

          message:
            "OTP not found. Please request a new OTP."

        });

      }


      /* =========================
         EXPIRY
      ========================= */

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


      /* =========================
         ATTEMPTS
      ========================= */

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


      /* =========================
         HASH COMPARE
      ========================= */

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


      /* =========================
         SUCCESS
      ========================= */

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


/* =================================
   UNKNOWN API
================================= */

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


/* =================================
   CLEANUP
================================= */

setInterval(
  () => {

    const now =
      Date.now();


    /* OTP CLEANUP */

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


    /* IP CLEANUP */

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


/* =================================
   START SERVER
================================= */

app.listen(
  PORT,
  () => {

    console.log(
      "================================"
    );

    console.log(
      "HRRYMODSONLINE BREVO OTP"
    );

    console.log(
      "Port:",
      PORT
    );

    console.log(
      "Brevo Sender:",
      BREVO_SENDER_EMAIL ||
      "NOT SET"
    );

    console.log(
      "Brevo API Key:",
      BREVO_API_KEY
        ? "SET"
        : "NOT SET"
    );

    console.log(
      "================================"
    );

  }
);
