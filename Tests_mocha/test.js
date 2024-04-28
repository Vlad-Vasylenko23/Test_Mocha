const assert = require('assert');
const bcrypt = require('bcrypt');
const { checkPasswordRequirements, hashPassword, compareWithHash } = require('./hashpassword');


describe('Password Functions', () => {
    describe('checkPasswordRequirements', () => {
        it('should return true for a valid password', () => {
            const validPassword = "!12345678Aa";
            assert.strictEqual(checkPasswordRequirements(validPassword), true);
        });

        it('should return false for a password shorter than 8 characters', () => {
            const invalidPassword = "!1234Aa";
            assert.strictEqual(checkPasswordRequirements(invalidPassword), false);
        });

        it('should return false for a password without uppercase letters', () => {
            const invalidPassword = "!12345678aa";
            assert.strictEqual(checkPasswordRequirements(invalidPassword), false);
        });

        it('should return false for a password without lowercase letters', () => {
            const invalidPassword = "!12345678AA";
            assert.strictEqual(checkPasswordRequirements(invalidPassword), false);
        });

        it('should return false for a password without numbers', () => {
            const invalidPassword = "!Abcdefgh";
            assert.strictEqual(checkPasswordRequirements(invalidPassword), false);
        });

        it('should return false for a password without special characters', () => {
            const invalidPassword = "Abcdefgh12345678";
            assert.strictEqual(checkPasswordRequirements(invalidPassword), false);
        });
    });

    describe('hashPassword and compareWithHash', () => {
        it('should hash and match a password correctly', async () => {
            const password = "!12345678Aa";
            const hashedPassword = await hashPassword(password);
            const match = await compareWithHash(hashedPassword, password);
            assert.strictEqual(match, true);
        });

        it('should not match a hashed password with an incorrect password', async () => {
            const password = "!12345678Aa";
            const incorrectPassword = "!12345678Bb";
            const hashedPassword = await hashPassword(password);
            const match = await compareWithHash(hashedPassword, incorrectPassword);
            assert.strictEqual(match, false);
        });
    });
});
