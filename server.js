const express = require("express");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 10000;

/*
  =========================
  CONFIGURATION
  =========================
*/

const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const RESEND_COOLDOWN_MS = 30 * 1000; // 30 seconds

/*
  Maximum OTP attempts per generated OTP
*/
const MAX_VERIFY_ATTEMPTS = 5;

/*
  Basic IP rate limit
*/
const RATE_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_IP = 10;

/*
  =========================
  SECURITY CHECK
  =========================
*/

if(!SMTP_USER || !SMTP_PASS){

  console.error(
    "ERROR: SMTP_USER and SMTP_PASS environment variables are required."
  );

}

/*
  =========================
  MIDDLEWARE
  =========================
*/

app.use(express.json({
  limit:"10kb"
}));

app.use(cors({
  origin:"*"
}));

/*
  =========================
  OTP STORAGE
  =========================

  For a demo/small gateway this in-memory
  storage is sufficient.

  IMPORTANT:
  Render restart will clear these OTPs.
*/

const otpStore = new Map();

/*
  IP request tracking
*/
const ipRequests = new Map();

/*
  =========================
  HELPERS
  =========================
*/

function normalizeEmail(email){

  return String(email || "")
    .trim()
    .toLowerCase();
}

function validEmail(email){

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOTP(){

  return crypto
    .randomInt(1000,10000)
    .toString();
}

function hashOTP(otp){

  return crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");
}

function getIP(req){

  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

/*
  =========================
  BASIC RATE LIMIT
  =========================
*/

function checkIPRateLimit(req){

  const ip = getIP(req);
  const now = Date.now();

  let record = ipRequests.get(ip);

  if(!record || now - record.start > RATE_WINDOW_MS){

    record = {
      start:now,
      count:0
    };

    ipRequests.set(ip,record);
  }

  record.count++;

  if(record.count > MAX_REQUESTS_PER_IP){

    return false;
  }

  return true;
}

/*
  =========================
  GMAIL TRANSPORTER
  =========================
*/

const transporter = nodemailer.createTransport({

  service:"gmail",

  auth:{
    user:SMTP_USER,
    pass:SMTP_PASS
  }
});

/*
  =========================
  HEALTH CHECK
  =========================
*/

app.get("/", (req,res)=>{

  res.json({
    status:"online",
    gateway:"hrrymodsonline",
    service:"Email OTP Gateway"
  });

});

/*
  =========================
  SEND OTP
  =========================
*/

app.post("/api/send-otp", async (req,res)=>{

  try{

    /*
      IP protection
    */

    if(!checkIPRateLimit(req)){

      return res.status(429).json({
        message:"Too many requests. Please try again later."
      });

    }

    const email = normalizeEmail(req.body.email);

    /*
      Validate email
    */

    if(!validEmail(email)){

      return res.status(400).json({
        message:"Please provide a valid email address."
      });

    }

    /*
      Existing OTP check
    */

    const existing = otpStore.get(email);

    if(existing){

      const remaining =
        RESEND_COOLDOWN_MS -
        (Date.now() - existing.createdAt);

      if(remaining > 0){

        return res.status(429).json({

          message:
            `Please wait ${Math.ceil(remaining / 1000)} seconds before requesting another OTP.`

        });

      }
    }

    /*
      Generate secure 4-digit OTP
    */

    const otp = generateOTP();

    /*
      Store only hash, NOT plain OTP
    */

    otpStore.set(email,{

      otpHash:hashOTP(otp),

      createdAt:Date.now(),

      expiresAt:
        Date.now() + OTP_EXPIRY_MS,

      attempts:0

    });

    /*
      Send email
    */

    await transporter.sendMail({

      from:`hrrymodsonline <${SMTP_USER}>`,

      to:email,

      subject:"Your hrrymodsonline OTP",

      text:
`Your hrrymodsonline verification OTP is: ${otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.`,

      html:`

<!DOCTYPE html>
<html>
<body style="margin:0;background:#f4f4f4;font-family:Arial,sans-serif">

<div style="
max-width:500px;
margin:30px auto;
background:#ffffff;
border-radius:16px;
padding:30px;
text-align:center;
">

<h2 style="margin-top:0">
hrrymodsonline
</h2>

<p>
Your verification OTP is:
</p>

<div style="
font-size:38px;
font-weight:bold;
letter-spacing:12px;
padding:20px;
background:#f5f5f5;
border-radius:12px;
margin:20px 0;
">

${otp}

</div>

<p style="color:#777">
This OTP expires in 5 minutes.
</p>

<p style="
font-size:12px;
color:#999;
margin-top:25px;
">

Do not share this OTP with anyone.

</p>

</div>

</body>
</html>

`

    });

    return res.json({

      success:true,

      message:"OTP sent successfully."

    });

  }catch(error){

    console.error("SEND OTP ERROR:",error);

    /*
      Remove OTP if email sending failed
    */

    const email = normalizeEmail(req.body.email);

    otpStore.delete(email);

    return res.status(500).json({

      message:
        "Unable to send OTP. Please try again later."

    });

  }

});

/*
  =========================
  VERIFY OTP
  =========================
*/

app.post("/api/verify-otp",(req,res)=>{

  try{

    if(!checkIPRateLimit(req)){

      return res.status(429).json({

        message:
          "Too many requests. Please try again later."

      });

    }

    const email =
      normalizeEmail(req.body.email);

    const otp =
      String(req.body.otp || "").trim();

    if(!validEmail(email)){

      return res.status(400).json({

        message:"Invalid email."

      });

    }

    if(!/^\d{4}$/.test(otp)){

      return res.status(400).json({

        message:"OTP must contain exactly 4 digits."

      });

    }

    const record =
      otpStore.get(email);

    if(!record){

      return res.status(400).json({

        message:
          "OTP not found. Please request a new OTP."

      });

    }

    /*
      Expiry
    */

    if(Date.now() > record.expiresAt){

      otpStore.delete(email);

      return res.status(400).json({

        message:
          "OTP has expired. Please request a new OTP."

      });

    }

    /*
      Maximum attempts
    */

    record.attempts++;

    if(record.attempts > MAX_VERIFY_ATTEMPTS){

      otpStore.delete(email);

      return res.status(429).json({

        message:
          "Too many incorrect attempts. Please request a new OTP."

      });

    }

    /*
      Constant-time comparison
    */

    const suppliedHash =
      hashOTP(otp);

    const storedHash =
      record.otpHash;

    const isValid =
      suppliedHash.length === storedHash.length &&
      crypto.timingSafeEqual(
        Buffer.from(suppliedHash),
        Buffer.from(storedHash)
      );

    if(!isValid){

      return res.status(400).json({

        message:"Incorrect OTP."

      });

    }

    /*
      OTP is one-time use
    */

    otpStore.delete(email);

    return res.json({

      success:true,

      verified:true,

      message:"Email verified successfully."

    });

  }catch(error){

    console.error("VERIFY ERROR:",error);

    return res.status(500).json({

      message:"Verification failed."

    });

  }

});

/*
  =========================
  CLEANUP
  =========================
*/

setInterval(()=>{

  const now = Date.now();

  /*
    Remove expired OTPs
  */

  for(const [email,record] of otpStore.entries()){

    if(now > record.expiresAt){

      otpStore.delete(email);

    }

  }

  /*
    Remove old IP records
  */

  for(const [ip,record] of ipRequests.entries()){

    if(now - record.start > RATE_WINDOW_MS){

      ipRequests.delete(ip);

    }

  }

},60 * 1000);

/*
  =========================
  START SERVER
  =========================
*/

app.listen(PORT,()=>{

  console.log(
    `hrrymodsonline OTP Gateway running on port ${PORT}`
  );

});
