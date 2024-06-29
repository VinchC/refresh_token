const express = require("express");
const multer = require("multer");

const app = express();

const port = 3000;

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

const jwt = require("jsonwebtoken");
const secretKey = "secret_key";

const authenticate = (req, res, next) => {
  const accessToken = req.headers["authorization"];
  const refreshToken = req.cookies["refreshToken"];

  if (!accessToken && !refreshToken) {
    return res.status(401).send("Access denied. No token provided.");
  }

  try {
    const decoded = jwt.verify(accessToken, secretKey);
    req.user = decoded.user;
    next();
  } catch (error) {
    if (!refreshToken) {
      return res.status(401).send("Access denied. No refresh token provided.");
    }
    try {
      const decoded = jwt.verify(refreshToken, secretKey);
      const accessToken = jwt.sign({ user: decoded.user }, secretKey, {
        expiresIn: "1h",
      });

      res
        .cookie("refreshToken", refreshToken, {
          httpOnly: true,
          sameSite: "strict",
        })
        .header("Authorization", accessToken)
        .send(decoded.user);
    } catch (error) {}
    return res.status(400).send("Invalid token");
  }
};

app.get(`/protected`, authenticate, (req, res) => {
  res.send(`Welcome to the protected route`);
});

app.post("/login", (req, res) => {
  const user = {
    id: 1,
    name: "john_doe",
  };

  const accessToken = jwt.sign({ user }, secretKey, { expiresIn: "1h" });
  const refreshToken = jwt.sign({ user }, secretKey, { expiresIn: "1d" });

  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
    })
    .header("Authorization", accessToken)
    .send(user);
});

app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies["refreshToken"];
  if (!refreshToken) {
    return sendStatus(401).send("Access denied. No refresh token provided.");
  }

  try {
    const decoded = jwt.verify(refreshToken, secretKey);
    const accessToken = jwt.sign({ user: decoded.user }, secretKey, {
      expiresIn: "1h",
    });

    res.header("Authorization", accessToken).send(decoded.user);
  } catch (error) {
    return res.status(400).send("Invalid refresh token.");
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/png" ||
      file.mimetype === "image/jpg"
    ) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type"));
    }
  },
});

app.post("/upload", upload.single("file"), (req, res) => {});
