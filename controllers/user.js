import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { sendCookie } from "../utils/features.js";

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    let user = await User.findOne({ email });

    if (user) return next(new ErrorHandler("User already exists", 404));

    const hashPassword = await bcrypt.hash(password, 10);

    user = await User.create({
      name,
      email,
      password: hashPassword,
    });

    sendCookie(user, 201, "User Added Successfully", res);
  } catch (error) {
    next(error);
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user)
      return next(new ErrorHandler("Incorrect Email or Password", 400));

    const isMatch = bcrypt.compare(password, user.password);

    if (!isMatch)
      return next(new ErrorHandler("Incorrect Email or Password", 404));

    sendCookie(user, 200, "Logged in Successfully", res);
  } catch (error) {
    next(error);
  }
};

export const logout = (req, res) => {
  return res
    .cookie("token", "", {
      expires: new Date(Date.now()),
      sameSite: process.env.NODE_ENV === "Development"? 'lax' : 'none',
      secure: process.env.NODE_ENV === "Development"? false : true,
    })
    .json({
      success: true,
      message: "Logged Out!",
    });
};

export const getMyProfile = (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
};
