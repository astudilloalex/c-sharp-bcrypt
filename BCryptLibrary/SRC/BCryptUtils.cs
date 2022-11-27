using System;

namespace BCryptLibrary.SRC
{
    /// <summary>
    /// BCrypt utils to hash passwords.
    /// </summary>
    internal class BCryptUtils
    {
        private readonly uint[] _pArray;
        private readonly uint[] _sArray;

        /// <summary>
        /// Define a BCryptUtils class.
        /// </summary>
        /// <param name="pArray">Initial contents of key schedule.</param>
        /// <param name="sArray">Contain information subkeys to cipher.</param>
        public BCryptUtils(uint[] pArray, uint[] sArray)
        {
            _pArray = (uint[])pArray.Clone();
            _sArray = (uint[])sArray.Clone();
        }

        /// <summary>
        /// Blowfish encipher a single 64-bit block encoded as two 32-bit halves.
        /// </summary>
        /// <param name="data">An array containing the two 32-bit half blocks.</param>
        /// <param name="off">The position in the array of the blocks.</param>
        private void Encipher(uint[] data, sbyte off)
        {
            byte blowfishRounds = Constants.BlowfishRounds;
            uint n;
            uint l = data[off];
            uint r = data[off + 1];
            l ^= _pArray[0];
            for (int i = 0; i <= blowfishRounds - 2;)
            {
                // Feistel substitution on left word.
                n = _sArray[(l >> 24) & 0xff];
                n += _sArray[0x100 | ((l >> 16) & 0xff)];
                n ^= _sArray[0x200 | ((l >> 8) & 0xff)];
                n += _sArray[0x300 | (l & 0xff)];
                r ^= n ^ _pArray[++i];

                // Feistel substitution on right word
                n = _sArray[(r >> 24) & 0xff];
                n += _sArray[0x100 | ((r >> 16) & 0xff)];
                n ^= _sArray[0x200 | ((r >> 8) & 0xff)];
                n += _sArray[0x300 | (r & 0xff)];
                l ^= n ^ _pArray[++i];
            }
            data[off] = r ^ _pArray[blowfishRounds + 1];
            data[off + 1] = l;
        }

        /// <summary>
        /// Perform the "enhanced key schedule" step described by Provos and Mazieres
        /// in "A Future-Adaptable Password Scheme" https://www.openbsd.org/papers/bcrypt-paper.ps.
        /// </summary>
        /// <param name="data">Salt information.</param>
        /// <param name="key">Password information.</param>
        /// <param name="signExtendBug">True to implement the 2x bug</param>
        /// <param name="safety">Bit 16 is set when the safety measure is requested</param>
        private void EnhancedKeySchedule(byte[] data, byte[] key, bool signExtendBug, int safety)
        {
            int i;
            uint[] keyOffPointer = { 0 };
            uint[] lr = { 0, 0 };
            uint[] dataOffPointer = { 0 };
            uint[] signPointer = { 0 };
            uint diff = 0;
            for (i = 0; i < _pArray.Length; i++)
            {
                uint[] words = StreamToWords(key, keyOffPointer, signPointer);
                diff |= words[0] ^ words[1];
                _pArray[i] = _pArray[i] ^ words[signExtendBug ? 1 : 0];
            }
            uint sign = signPointer[0];
            /*
		    * At this point, "diff" is zero iff the correct and buggy algorithms produced
		    * exactly the same result. If so and if "sign" is non-zero, which indicates that
		    * there was a non-benign sign extension, this means that we have a collision
		    * between the correctly computed hash for this password and a set of passwords
		    * that could be supplied to the buggy algorithm. Our safety measure is meant to
		    * protect from such many-buggy to one-correct collisions, by deviating from the
		    * correct algorithm in such cases. Let's check for this.
		    */
            diff |= diff >> 16; /* still zero iff exact match */
            diff &= 0xffff; /* ditto */
            diff += 0xffff; /* bit 16 set iff "diff" was non-zero (on non-match) */
            sign <<= 9; /* move the non-benign sign extension flag to bit 16 */
            sign &= ~diff & (uint)safety; /* action needed? */
            /*
		    * If we have determined that we need to deviate from the correct algorithm, flip
		    * bit 16 in initial expanded key. (The choice of 16 is arbitrary, but let's stick
		    * to it now. It came out of the approach we used above, and it's not any worse
		    * than any other choice we could make.)
		    *
		    * It is crucial that we don't do the same to the expanded key used in the main
		    * Eksblowfish loop. By doing it to only one of these two, we deviate from a state
		    * that could be directly specified by a password to the buggy algorithm (and to
		    * the fully correct one as well, but that's a side-effect).
		    */
            _pArray[0] ^= sign;
            for (i = 0; i < _pArray.Length; i += 2)
            {
                lr[0] ^= StreamToWord(data, dataOffPointer);
                lr[1] ^= StreamToWord(data, dataOffPointer);
                Encipher(lr, 0);
                _pArray[i] = lr[0];
                _pArray[i + 1] = lr[1];
            }
            for (i = 0; i < _sArray.Length; i += 2)
            {
                lr[0] ^= StreamToWord(data, dataOffPointer);
                lr[1] ^= StreamToWord(data, dataOffPointer);
                Encipher(lr, 0);
                _sArray[i] = lr[0];
                _sArray[i + 1] = lr[1];
            }
        }

        /// <summary>
        /// Key the Blowfish cipher.
        /// </summary>
        /// <param name="key">An array containing the key</param>
        /// <param name="signExtendBug">true to implement the 2x bug</param>
        /// <param name="safety">Bit 16 is set when the safety measure is requested.</param>
        private void Key(byte[] key, bool signExtendBug)
        {
            int i;
            uint[] keyOffPointer = { 0 };
            uint[] data = { 0, 0 };

            for (i = 0; i < _pArray.Length; i++)
            {
                if (!signExtendBug)
                {
                    _pArray[i] = _pArray[i] ^ StreamToWord(key, keyOffPointer);
                }
                else
                {
                    _pArray[i] = _pArray[i] ^ StreamToWordBug(key, keyOffPointer);
                }
            }

            for (i = 0; i < _pArray.Length; i += 2)
            {
                Encipher(data, 0);
                _pArray[i] = data[0];
                _pArray[i + 1] = data[1];
            }

            for (i = 0; i < _sArray.Length; i += 2)
            {
                Encipher(data, 0);
                _sArray[i] = data[0];
                _sArray[i + 1] = data[1];
            }
        }

        /// <summary>
        /// Cycically extract a word of key material.
        /// </summary>
        /// <param name="data">
        /// The bytes of the string to extract the data from <c>offsetPointer</c>
        /// (as a one-entry array) to the current offset into data.
        /// </param>
        /// <param name="offsetPointer">
        /// Array with offset for the current <c>data</c>.
        /// </param>
        /// <returns>A correct and buggy next word of material from <c>data</c> as <c>uint[]</c> with length 2.</returns>
        private static uint StreamToWord(byte[] data, uint[] offsetPointer)
        {
            uint[] signPointer = { 0 };
            return StreamToWords(data, offsetPointer, signPointer)[0];
        }

        /// <summary>
        /// Cycically extract a word of key material, with sign-extension bug
        /// </summary>
        /// <param name="data">The string to extract the data from.</param>
        /// <param name="offsetPointer">A "pointer" (as a one-entry array) to the current offset into data.</param>
        /// <returns>The next word of material from data.</returns>
        private static uint StreamToWordBug(byte[] data, uint[] offsetPointer)
        {
            uint[] signPointer = { 0 };
            return StreamToWords(data, offsetPointer, signPointer)[1];
        }

        /// <summary>
        /// Cycically extract a word of key material.
        /// </summary>
        /// <param name="data">The string to extract the data from</param>
        /// <param name="offsetPointer">A "pointer" (as a one-entry array) to the current offset into data.</param>
        /// <param name="signPointer">A "pointer" (as a one-entry array) to the cumulative flag for non-benign sign extension.</param>
        /// <returns>Correct and buggy next word of material from data as int[2]</returns>
        private static uint[] StreamToWords(byte[] data, uint[] offsetPointer, uint[] signPointer)
        {
            int i;
            uint[] words = { 0, 0 };
            uint off = offsetPointer[0];
            uint sign = signPointer[0];
            for (i = 0; i < 4; i++)
            {
                words[0] = (words[0] << 8) | ((uint)data[off] & 0xff);
                words[1] = (words[1] << 8) | (byte)data[off];// sign extension bug
                if (i > 0)
                {
                    sign |= words[1] & 0x80;
                }
                off = (uint)((off + 1) % data.Length);
            }
            offsetPointer[0] = off;
            signPointer[0] = sign;
            return words;
        }

        /// <summary>
        /// Perform the central password hashing step in the BCrypt schema.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The binary salt to hash with the password.</param>
        /// <param name="logRounds">The binary logarithm of the number.</param>
        /// <returns>An array containing the binary hashed password.</returns>
        /// <exception cref="ArgumentException">
        /// When enter bad <c>logRounds</c> <4 or >31.
        /// When enter bad <c>salt</c> length != 16.
        /// </exception>
        public byte[] CryptRaw(byte[] password, byte[] salt, int logRounds, bool signExtendBug, int safety)
        {
            if (logRounds < Constants.MinLogRounds || logRounds > Constants.MaxLogRounds)
            {
                throw new ArgumentException("Bad number of rounds", nameof(logRounds));
            }
            if (salt.Length != Constants.SaltLength)
            {
                throw new ArgumentException("Bad salt length", nameof(salt));
            }
            int i;
            int j;
            uint[] data = (uint[])BCryptArrays.BFCryptCiphertext.Clone();
            int dataLength = data.Length;
            int rounds = 1 << logRounds;
            EnhancedKeySchedule(salt, password, signExtendBug, safety);
            for (i = 0; i < rounds; i++)
            {
                Key(password, signExtendBug);
                Key(salt, false);
            }
            for (i = 0; i < 64; i++)
            {
                for (j = 0; j < (dataLength >> 1); j++)
                {
                    Encipher(data, (sbyte)(j << 1));
                }
            }
            byte[] cryptData = new byte[dataLength * 4];
            for (i = 0, j = 0; i < dataLength; i++)
            {
                cryptData[j++] = (byte)((data[i] >> 24) & 0xff);
                cryptData[j++] = (byte)((data[i] >> 16) & 0xff);
                cryptData[j++] = (byte)((data[i] >> 8) & 0xff);
                cryptData[j++] = (byte)(data[i] & 0xff);
            }
            return cryptData;
        }
    }
}