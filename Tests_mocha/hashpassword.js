const bcrypt = require('bcrypt');

function checkPasswordRequirements(password) {
    if (password.length < 8) {
        return false;
    }
    
    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
        return false;
    }
    
    if (!/\d/.test(password)) {
        return false;
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        return false;
    }
    return true;
}

async function hashPassword(password) {
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    } catch (error) {
        throw error;
    }
}

async function compareWithHash(hash, password) {
    try {
        const match = await bcrypt.compare(password, hash);
        return match;
    } catch (error) {
        throw error;
    }
}

// Example usage:
(async () => {
    const password = "!12345678Aa";

    // Check if password meets requirements
    if (!checkPasswordRequirements(password)) {
        console.log("Password does not meet requirements.");
        return;
    }

    // Hash the password
    try {
        const hashedPassword = await hashPassword(password);
        console.log("Hashed password:", hashedPassword);

        // Simulating password verification
        const passwordToCompare = "!12345678Aa";
        const isMatch = await compareWithHash(hashedPassword, passwordToCompare);
        console.log("Password matches hash:", isMatch);
    } catch (error) {
        console.error("Error:", error.message);
    }
})();

module.exports = { checkPasswordRequirements, hashPassword, compareWithHash };