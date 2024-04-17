
import { User } from "../models/userModel.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";

export const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required",
                success: false
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password",
                success: false
            });
        }

        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid email or password",
                success: false
            });
        }

        const token = jwt.sign({ id: user._id }, "your_secret_key", { expiresIn: "1h" });

        return res.status(200).cookie("token", token).json({
            message: `Welcome back ${user.fullName}`,
            user,
            success: true
        });

    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({
            message: "Server error",
            success: false
        });
    }
}

export const Logout = async (req, res) => {
    try {
        return res.status(200).cookie("token", "", { expires: new Date(0), httpOnly: true }).json({
            message: "User logged out successfully",
            success: true
        });
    } catch (error) {
        console.error("Logout error:", error);
        return res.status(500).json({
            message: "Server error",
            success: false
        });
    }
}

export const Register = async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) {
            return res.status(400).json({
                message: "Full name, email, and password are required",
                success: false
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                message: "Email is already registered",
                success: false
            });
        }

        const hashedPassword = await bcryptjs.hash(password, 10);

        await User.create({
            fullName,
            email,
            password: hashedPassword
        });

        return res.status(201).json({
            message: "Account created successfully",
            success: true
        });

    } catch (error) {
        console.error("Registration error:", error);
        return res.status(500).json({
            message: "Server error",
            success: false
        });
    }
};

