import React, {useState} from "react";

const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [jwt, setJwt] = useState("");
    const [profile, setProfile] = useState(null);

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
                console.log(data);
                setJwt(data.jwtToken);
                setMessage("Login successful");
                fetchUserProfile(data.jwtToken);
            } else {
                setMessage("Login failed. Please check your credentials.");
            }
        } catch (error) {
            console.log("Error: " + error);
            setMessage("An error occurred. Please try again.");
        }
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
                console.log(data);
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