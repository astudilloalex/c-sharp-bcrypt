// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

using BCryptLibrary.SRC;
using System.Security.Cryptography;
using System.Text;

namespace BCryptLibrary
{
    /// <summary>
    /// BCrypt implements OpenBSD-style Blowfish password hashing using
    /// the scheme described in "A Future-Adaptable Password Scheme" by
    /// Niels Provos and David Mazieres.
    /// 
    /// This is a JBCrypt modified class.
    /// </summary>
    public class BCrypt
    {
        /// <summary>
        /// Look up the 3 bits base64-encoded by the specified character,
        /// range-checking againt conversion table.
        /// </summary>
        /// <param name="c">The base64-encoded value.</param>
        /// <returns>The decoded value of c.</returns>
        private static sbyte Char64(char c)
        {
            sbyte[] index64 = BCryptArrays.Base64Decoding;
            if (c < 0 || c >= index64.Length) return -1;
            return index64[c];
        }

        /// <summary>
        /// Check that a plaintext password matches a previously hashed one.
        /// </summary>
        /// <param name="text">The plaintext password to verify.</param>
        /// <param name="hashed">The previously-hashed password.</param>
        /// <returns>True if the passwords match, false otherwise.</returns>
        public static bool CheckPassword(string text, string hashed)
        {
            byte[] textBytes;
            byte[] hashedBytes;
            try
            {
                string hashedPassword = HashPassword(text, hashed);
                hashedBytes = Encoding.UTF8.GetBytes(hashed);
                textBytes = Encoding.UTF8.GetBytes(hashedPassword);
            }
            catch
            {
                return false;
            }
            if (textBytes.Length != hashedBytes.Length) return false;
            byte result = 0;
            for (int i = 0; i < textBytes.Length; i++) result |= (byte)(hashedBytes[i] ^ textBytes[i]);
            return result == 0;
        }

        /// <summary>
        /// Decode a data encoded using bcrypt's base64 scheme to a byte array with
        /// the max length number of bytes to decode.
        /// 
        /// Note that this is not compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <param name="data">The string to decode.</param>
        /// <param name="maxLength">The maximum number of bytes to decode.</param>
        /// <returns>An array containing the decoded bytes.</returns>
        /// <exception cref="ArgumentException">When <c>maxLength</c> is zero or minor.</exception>
        private static byte[] DecodeBase64(string data, int maxLength)
        {
            if (maxLength <= 0)
            {
                throw new ArgumentException("Invalid max length", nameof(maxLength));
            }
            int dataLength = data.Length;
            sbyte char1;
            sbyte char2;
            sbyte char3;
            sbyte char4;
            sbyte mainChar;
            int length = 0;
            int off = 0;
            StringBuilder stringBuilder = new();
            while (off < dataLength - 1 && length < maxLength)
            {
                char1 = Char64(data[off++]);
                char2 = Char64(data[off++]);
                if (char1 == -1 || char2 == -1) break;
                mainChar = (sbyte)(char1 << 2);
                mainChar |= (sbyte)((char2 & 0x30) >> 4);
                stringBuilder.Append((char)mainChar);
                if (++length >= maxLength || off >= dataLength) break;
                char3 = Char64(data[off++]);
                if (char3 == -1) break;
                mainChar = (sbyte)((char2 & 0x0f) << 4);
                mainChar |= (sbyte)((char3 & 0x3c) >> 2);
                stringBuilder.Append((char)mainChar);
                if (++length >= maxLength || off >= dataLength) break;
                char4 = Char64(data[off++]);
                mainChar = (sbyte)((char3 & 0x03) << 6);
                mainChar |= char4;
                stringBuilder.Append((char)mainChar);
                ++length;
            }
            byte[] decodeData = new byte[length];
            char[] chars = stringBuilder.ToString().ToCharArray();
            for (off = 0; off < length; off++)
            {
                decodeData[off] = (byte)chars[off];
            }
            return decodeData;
        }

        /// <summary>
        /// Encode a byte array using bcrypt's slightly-modified base64
        /// encoding scheme.Note that this is *not* compatible with
        /// the standard MIME-base64 encoding.
        /// </summary>
        /// <param name="data">The byte array to encode.</param>
        /// <param name="length">The number of bytes to encode.</param>
        /// <returns>The base64-encoded string.</returns>
        /// <exception cref="ArgumentException">If the <c>length</c> is invalid</exception>
        private static void EncodeBase64(byte[] data, int length, StringBuilder stringBuilder)
        {
            if (length <= 0 || length > data.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }
            int off = 0;
            sbyte char1;
            sbyte char2;
            char[] chars = BCryptArrays.Base64Encode;
            while (off < length)
            {
                char1 = (sbyte)(data[off++] & 0xff);
                stringBuilder.Append(chars[(char1 >> 2) & 0x3f]);
                char1 = (sbyte)((char1 & 0x03) << 4);
                if (off >= length)
                {
                    stringBuilder.Append(chars[char1 & 0x3f]);
                    break;
                }
                char2 = (sbyte)(data[off++] & 0xff);
                char1 |= (sbyte)((char2 >> 4) & 0x0f);
                stringBuilder.Append(chars[char1 & 0x3f]);
                char1 = (sbyte)((char2 & 0x0f) << 2);
                if (off >= length)
                {
                    stringBuilder.Append(chars[char1 & 0x3f]);
                    break;
                }
                char2 = (sbyte)(data[off++] & 0xff);
                char1 |= (sbyte)((char2 >> 6) & 0x03);
                stringBuilder.Append(chars[char1 & 0x3f]);
                stringBuilder.Append(chars[char2 & 0x3f]);
            }
        }

        // <summary>
        // Generate a salt for use with the <c>BCrypt.HashPassword()</c> method.
        // </summary>
        // <param name="logRounds">
        // The log2 of the number of rounds of hashing to apply - the work factor therefore increases as
        // 2**<c>logRounds</c>.
        // </param>
        // <param name="secureRandom">An instance of RandomNumberGenerator to use.</param>
        // <returns>An encoded salt value.</returns>
        // <exception cref="ArgumentException">
        // When <c>logRounds</c> are incorrect (<4 or >30).
        // </exception>
        //public static string GenSalt(byte logRounds, RandomNumberGenerator secureRandom)
        //{
        //    if (logRounds < Constants.MinLogRounds || logRounds >= Constants.MaxLogRounds)
        //    {
        //        throw new ArgumentException("Invalid Log Rounds", nameof(logRounds));
        //    }
        //    byte[] rounds = RandomNumberGenerator.GetBytes(Constants.SaltLength);
        //    StringBuilder stringBuilder = new();
        //    stringBuilder.Append("$2a$");
        //    if (logRounds < 10) stringBuilder.Append('0');
        //    stringBuilder.Append(logRounds);
        //    stringBuilder.Append('$');
        //    stringBuilder.Append(EncodeBase64(rounds, rounds.Length));
        //    return stringBuilder.ToString();
        //}

        /// <summary>
        /// Generate a salt for use with the <c>BCrypt.HashPassword()</c> method.
        /// </summary>
        /// <param name="logRounds">
        /// The log2 of the number of rounds of hashing to apply - the work factor therefore increases as
        /// 2**<c>logRounds</c>.
        /// </param>
        /// <returns>An encoded salt value.</returns>
        public static string GenSalt(byte logRounds)
        {
            if (logRounds < Constants.MinLogRounds || logRounds >= Constants.MaxLogRounds)
            {
                throw new ArgumentException("Invalid Log Rounds", nameof(logRounds));
            }
            byte[] rounds = RandomNumberGenerator.GetBytes(Constants.SaltLength);
            StringBuilder stringBuilder = new();
            stringBuilder.Append("$2a$");
            if (logRounds < 10) stringBuilder.Append('0');
            stringBuilder.Append(logRounds);
            stringBuilder.Append('$');
            EncodeBase64(rounds, rounds.Length, stringBuilder);
            return stringBuilder.ToString();
        }

        /// <summary>
        /// Generate a salt for use with the <c>BCrypt.HashPassword()</c> method,
        /// selecting a reasonable default for the number of hashing
        /// rounds to apply.
        /// </summary>
        /// <returns>An encoded salt value.</returns>
        public static string GenSalt()
        {
            return GenSalt(Constants.SaltDefaultLogRounds);
        }

        /// <summary>
        /// Hash a password using the OpenBSD bcrypt scheme.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">
        /// The salt to hash with (perhaps generated using <c>BCrypt.GenSalt</c>.
        /// </param>
        /// <returns>The hashed password.</returns>
        /// <exception cref="ArgumentException">
        /// When <c>salt</c> length is invalid (<28).
        /// When <c>salt</c> version is invalid.
        /// When <c>salt</c> revision is invalid.
        /// When <c>salt</c> rounds is missing.
        /// </exception>
        public static string HashPassword(string password, string salt)
        {
            return HashPassword(Encoding.UTF8.GetBytes(password), salt);
        }

        /// <summary>
        /// ash a password using the OpenBSD bcrypt scheme.
        /// </summary>
        /// <param name="passwordBytes">The password to hash, as a byte array.</param>
        /// <param name="salt">The salt to hash with (perhaps generated using BCrypt.GenSalt)</param>
        /// <returns>The hashed password</returns>
        /// <exception cref="ArgumentException"></exception>
        public static string HashPassword(byte[] passwordBytes, string salt)
        {
            BCryptUtils bCryptUtils;
            string realSalt;
            byte[] saltb;
            byte[] hashed;
            char minor = (char)0;
            int rounds, off;
            int saltLength = salt.Length;
            StringBuilder builder = new();
            if (saltLength < 28)
            {
                throw new ArgumentException("Invalid salt length", nameof(salt));
            }
            if (salt[0] != '$' || salt[1] != '2')
            {
                throw new ArgumentException("Invalid salt version", nameof(salt));
            }
            if (salt[2] == '$')
            {
                off = 3;
            }
            else
            {
                minor = salt[2];
                if ((minor != 'a' && minor != 'x' && minor != 'y' && minor != 'b') || salt[3] != '$')
                {
                    throw new ArgumentException("Invalid salt revision", nameof(salt));
                }
                off = 4;
            }

            // Extract number of rounds
            if (salt[off + 2] > '$')
            {
                throw new ArgumentException("Missing salt rounds", nameof(salt));
            }
            if (off == 4 && saltLength < 29)
            {
                throw new ArgumentException("Invalid salt", nameof(salt));
            }
            rounds = int.Parse(salt.Substring(off, 2));
            realSalt = salt.Substring(startIndex: off + 3);
            saltb = DecodeBase64(realSalt, Constants.SaltLength).ToArray();
            if (minor >= 'a')
            {
                byte[] tempPassword = new byte[passwordBytes.Length + 1];
                for (int i = 0; i < passwordBytes.Length; i++) tempPassword[i] = passwordBytes[i];
                tempPassword[^1] = 0;
                passwordBytes = tempPassword;
            }

            bCryptUtils = new BCryptUtils(BCryptArrays.PArray, BCryptArrays.SArray);
            hashed = bCryptUtils.CryptRaw(passwordBytes, saltb, rounds, minor == 'x', minor == 'a' ? 0x10000 : 0);
            builder.Append("$2");
            if (minor >= 'a')
            {
                builder.Append(minor);
            }
            builder.Append('$');
            if (rounds < 10)
            {
                builder.Append('0');
            }
            builder.Append(rounds);
            builder.Append('$');
            EncodeBase64(saltb, saltb.Length, builder);
            EncodeBase64(hashed, BCryptArrays.BFCryptCiphertext.Length * 4 - 1, builder);
            return builder.ToString();
        }
    }
}