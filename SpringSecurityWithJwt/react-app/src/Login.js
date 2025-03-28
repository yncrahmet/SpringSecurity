import React, { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [jwt, setJwt] = useState("");
    const [profile, setProfile] = useState(null);
    const location = useLocation();
    const navigate = useNavigate();

    useEffect(() => {
        const params = new URLSearchParams(location.search);
        const email = params.get("email");
        if (email) {
            fetch(`http://localhost:8080/google-callback?email=${email}`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                },
            })
                .then((response) => {
                    if (response.ok) {
                        return response.json();
                    } else {
                        throw new Error("Failed to fetch token from /google-callback");
                    }
                })
                .then(async (data) => {
                    setJwt(data.token);
                    setMessage("Google login successful");
                    await fetchUserProfile(data.token);
                })
                .catch((error) => {
                    console.error("Error:", error);
                    setMessage("An error occurred during Google login: " + error.message);
                });
        }
    }, [location]);

    const handleLogin = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch("http://localhost:8080/signin", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            if (response.ok) {
                const data = await response.json();
                setJwt(data.jwtToken);
                setMessage("Login successful");
                await fetchUserProfile(data.jwtToken);
            } else {
                setMessage("Login failed. Please check your credentials.");
            }
        } catch (error) {
            console.log("Error: " + error);
            setMessage("An error occurred. Please try again.");
        }
    };

    const handleGoogleLogin = () => {
        window.location.href = "http://localhost:8080/oauth2/authorization/google";
    };

    const fetchUserProfile = async (token) => {
        try {
            const response = await fetch("http://localhost:8080/profile", {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                setProfile(data);
            } else {
                setMessage("Failed to fetch the profile.");
            }
        } catch (error) {
            console.log("Error: " + error);
            setMessage("An error occurred. Please try again.");
        }
    };

    return (
        <div className="login-container">
            {!profile ? (
                <>
                    <h2>Login</h2>
                    <form onSubmit={handleLogin} className="login-form">
                        <div className="form-group">
                            <label>Username</label>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                placeholder="Enter username"
                            />
                        </div>
                        <div className="form-group">
                            <label>Password</label>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter password"
                            />
                        </div>
                        <button type="submit">Login</button>
                    </form>
                    <p className="or-divider">OR</p>
                    <button onClick={handleGoogleLogin} className="google-login-button">
                        Login with Google
                    </button>
                </>
            ) : (
                <div className="profile-card">
                    <h3>User Profile</h3>
                    <p>
                        <strong>Username:</strong> {profile.username}
                    </p>
                    <p>
                        <strong>Roles:</strong> {profile.roles.join(", ")}
                    </p>
                    <p>
                        <strong>Message:</strong> {profile.message}
                    </p>
                </div>
            )}
            {message && <p className="message">{message}</p>}
            {jwt && <p className="jwt-token">{jwt}</p>}
        </div>
    );
};

export default Login;