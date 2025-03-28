import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Login from "./Login";
import "./App.css";

function App() {
    return (
        <Router>
            <div className="App">
                <h1>JWT Authentication Demo</h1>
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="/" element={<Login />} />
                </Routes>
            </div>
        </Router>
    );
}

export default App;