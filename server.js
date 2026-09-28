const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;


/*
==================================================
CONFIG
==================================================
*/

const SMTP_USER =
  process.env.SMTP_USER;

const SMTP_PASS =
  process.env.SMTP_PASS;


/*
OTP validity:
5 minutes
*/

const OTP_EXPIRY =
  5 * 60 * 1000;


/*
Resend:
30 seconds
*/

const RESEND_COOLDOWN =
  30 * 1000;


/*
Maximum wrong OTP attempts
*/

const MAX_ATTEMPTS = 5;


/*
Basic IP rate limit
*/

const RATE_WINDOW =
  60 * 1000;

const MAX_IP_REQUESTS = 10;


/*
==================================================
STARTUP CHECK
==================================================
*/

if(!SMTP_USER || !SMTP_PASS){

  console.error(
    "WARNING: SMTP_USER or SMTP_PASS is missing."
  );

}


/*
==================================================
MIDDLEWARE
==================================================
*/

app.use(
  express.json({
    limit:"10kb"
  })
);


app.use(
  cors({
    origin:"*",

    methods:[
      "GET",
      "POST",
      "OPTIONS"
    ],

    allowedHeaders:[
      "Content-Type",
      "Accept"
    ]
  })
);


/*
==================================================
OTP MEMORY
==================================================
*/

const otpStore =
  new Map();


/*
==================================================
IP RATE LIMIT MEMORY
==================================================
*/

const ipStore =
  new Map();


/*
==================================================
EMAIL VALIDATION
==================================================
*/

function normalizeEmail(email){

  return String(email || "")
    .trim()
    .toLowerCase();

}


function validEmail(email){

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);

}


/*
==================================================
GENERATE 4 DIGIT OTP
==================================================
*/

function generateOTP(){

  return crypto
    .randomInt(
      1000,
      10000
    )
    .toString();

}


/*
==================================================
HASH OTP
==================================================
*/

function hashOTP(otp){

  return crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");

}


/*
==================================================
GET IP
==================================================
*/

function getIP(req){

  const forwarded =
    req.headers["x-forwarded-for"];

  if(forwarded){

    return forwarded
      .split(",")[0]
      .trim();

  }

  return (
    req.socket.remoteAddress ||
    "unknown"
  );

}


/*
==================================================
RATE LIMIT
==================================================
*/

function allowedRequest(req){

  const ip =
    getIP(req);

  const now =
    Date.now();


  let record =
    ipStore.get(ip);


  if(
    !record ||
    now - record.start >
    RATE_WINDOW
  ){

    record = {

      start:now,

      count:0

    };


    ipStore.set(
      ip,
      record
    );

  }


  record.count++;


  if(
    record.count >
    MAX_IP_REQUESTS
  ){

    return false;

  }


  return true;

}


/*
==================================================
GMAIL
==================================================
*/

const transporter =
  nodemailer.createTransport({

    service:"gmail",

    auth:{

      user:SMTP_USER,

      pass:SMTP_PASS

    }

  });


/*
==================================================
ROOT
==================================================
*/

app.get(
  "/",
  (req,res)=>{

    res.status(200).json({

      status:"online",

      gateway:
        "hrrymodsonline",

      service:
        "Email OTP Gateway"

    });

  }
);


/*
==================================================
HEALTH
==================================================
*/

app.get(
  "/health",
  (req,res)=>{

    res.status(200).json({

      ok:true,

      gateway:
        "hrrymodsonline"

    });

  }
);


/*
==================================================
SEND OTP
==================================================
*/

app.post(
  "/api/send-otp",
  async(req,res)=>{

    try{

      /*
      IP protection
      */

      if(
        !allowedRequest(req)
      ){

        return res
          .status(429)
          .json({

            success:false,

            message:
              "Too many requests. Please try again later."

          });

      }


      /*
      Email
      */

      const email =
        normalizeEmail(
          req.body.email
        );


      /*
      Validate
      */

      if(
        !validEmail(email)
      ){

        return res
          .status(400)
          .json({

            success:false,

            message:
              "Please enter a valid email address."

          });

      }


      /*
      Existing OTP
      */

      const oldOTP =
        otpStore.get(email);


      if(oldOTP){

        const elapsed =
          Date.now() -
          oldOTP.createdAt;


        if(
          elapsed <
          RESEND_COOLDOWN
        ){

          const wait =
            Math.ceil(
              (
                RESEND_COOLDOWN -
                elapsed
              ) / 1000
            );


          return res
            .status(429)
            .json({

              success:false,

              message:
                `Please wait ${wait} seconds before requesting another OTP.`

            });

        }

      }


      /*
      Generate
      */

      const otp =
        generateOTP();


      /*
      Store hashed OTP
      */

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

          attempts:0

        }
      );


      /*
      Send email
      */

      await transporter.sendMail({

        from:
          `hrrymodsonline <${SMTP_USER}>`,

        to:
          email,

        subject:
          "Your hrrymodsonline OTP",

        text:
`Your hrrymodsonline verification OTP is: ${otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.`,

        html:

`
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

</head>

<body
style="
margin:0;
padding:20px;
background:#f3f3f3;
font-family:Arial,Helvetica,sans-serif;
"
>

<div
style="
max-width:500px;
margin:auto;
background:#ffffff;
border-radius:18px;
padding:30px;
text-align:center;
"
>

<h2
style="
margin:0 0 10px;
color:#111;
"
>

hrrymodsonline

</h2>


<p
style="
color:#555;
font-size:15px;
"
>

Your email verification OTP is:

</p>


<div
style="
font-size:38px;
font-weight:bold;
letter-spacing:12px;
padding:20px;
margin:20px 0;
background:#f5f5f5;
border-radius:14px;
color:#111;
"
>

${otp}

</div>


<p
style="
color:#777;
font-size:14px;
"
>

This OTP expires in 5 minutes.

</p>


<p
style="
color:#999;
font-size:12px;
"
>

Do not share this OTP with anyone.

</p>

</div>

</body>

</html>
`

      });


      /*
      Success
      */

      return res
        .status(200)
        .json({

          success:true,

          message:
            "OTP sent successfully."

        });


    }catch(error){

      console.error(
        "SEND OTP ERROR:",
        error
      );


      /*
      Remove failed OTP
      */

      const email =
        normalizeEmail(
          req.body.email
        );


      otpStore.delete(
        email
      );


      return res
        .status(500)
        .json({

          success:false,

          message:
            "Unable to send OTP. Please check the Render email configuration."

        });

    }

  }
);


/*
==================================================
VERIFY OTP
==================================================
*/

app.post(
  "/api/verify-otp",
  (req,res)=>{

    try{

      /*
      Rate limit
      */

      if(
        !allowedRequest(req)
      ){

        return res
          .status(429)
          .json({

            success:false,

            message:
              "Too many requests. Please try again later."

          });

      }


      /*
      Input
      */

      const email =
        normalizeEmail(
          req.body.email
        );


      const otp =
        String(
          req.body.otp || ""
        ).trim();


      /*
      Validate email
      */

      if(
        !validEmail(email)
      ){

        return res
          .status(400)
          .json({

            success:false,

            message:
              "Invalid email address."

          });

      }


      /*
      Validate OTP
      */

      if(
        !/^\d{4}$/.test(otp)
      ){

        return res
          .status(400)
          .json({

            success:false,

            message:
              "OTP must contain exactly 4 digits."

          });

      }


      /*
      Find OTP
      */

      const record =
        otpStore.get(email);


      if(!record){

        return res
          .status(400)
          .json({

            success:false,

            message:
              "OTP not found. Please request a new OTP."

          });

      }


      /*
      Expiry
      */

      if(
        Date.now() >
        record.expiresAt
      ){

        otpStore.delete(
          email
        );


        return res
          .status(400)
          .json({

            success:false,

            message:
              "OTP has expired. Please request a new OTP."

          });

      }


      /*
      Attempts
      */

      record.attempts++;


      if(
        record.attempts >
        MAX_ATTEMPTS
      ){

        otpStore.delete(
          email
        );


        return res
          .status(429)
          .json({

            success:false,

            message:
              "Too many incorrect attempts. Please request a new OTP."

          });

      }


      /*
      Hash entered OTP
      */

      const enteredHash =
        hashOTP(otp);


      const savedHash =
        record.otpHash;


      /*
      Secure comparison
      */

      const valid =
        enteredHash.length ===
          savedHash.length &&

        crypto.timingSafeEqual(

          Buffer.from(
            enteredHash
          ),

          Buffer.from(
            savedHash
          )

        );


      if(!valid){

        return res
          .status(400)
          .json({

            success:false,

            message:
              "Incorrect OTP."

          });

      }


      /*
      OTP one-time use
      */

      otpStore.delete(
        email
      );


      /*
      Success
      */

      return res
        .status(200)
        .json({

          success:true,

          verified:true,

          message:
            "Email verified successfully."

        });


    }catch(error){

      console.error(
        "VERIFY OTP ERROR:",
        error
      );


      return res
        .status(500)
        .json({

          success:false,

          message:
            "Verification failed. Please try again."

        });

    }

  }
);


/*
==================================================
UNKNOWN API ROUTES
==================================================
*/

app.use(
  "/api",
  (req,res)=>{

    res
      .status(404)
      .json({

        success:false,

        message:
          "API endpoint not found."

      });

  }
);


/*
==================================================
GENERAL ERROR HANDLER
==================================================
*/

app.use(
  (err,req,res,next)=>{

    console.error(
      "SERVER ERROR:",
      err
    );


    res
      .status(500)
      .json({

        success:false,

        message:
          "Internal server error."

      });

  }
);


/*
==================================================
CLEANUP
==================================================
*/

setInterval(
  ()=>{

    const now =
      Date.now();


    /*
    Delete expired OTPs
    */

    for(
      const [
        email,
        record
      ]
      of otpStore.entries()
    ){

      if(
        now >
        record.expiresAt
      ){

        otpStore.delete(
          email
        );

      }

    }


    /*
    Delete old IP records
    */

    for(
      const [
        ip,
        record
      ]
      of ipStore.entries()
    ){

      if(
        now - record.start >
        RATE_WINDOW
      ){

        ipStore.delete(
          ip
        );

      }

    }

  },

  60 * 1000
);


/*
==================================================
START
==================================================
*/

app.listen(
  PORT,
  ()=>{

    console.log(
      `hrrymodsonline OTP Gateway running on port ${PORT}`
    );

  }
);
