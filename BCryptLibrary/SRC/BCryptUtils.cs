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
            _pArray = pArray;
            _sArray = sArray;
        }

        /// <summary>
        /// Blowfish encipher a single 64-bit block encoded as two 32-bit halves.
        /// </summary>
        /// <param name="data">An array containing the two 32-bit half blocks.</param>
        /// <param name="off">The position in the array of the blocks.</param>
        private void Encipher(uint[] data, byte off)
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
        private void EnhancedKeySchedule(byte[] data, byte[] key)
        {

            uint[] keyOffPointer = new uint[] { 0 };
            uint[] lr = new uint[] { 0, 0 };
            uint[] dataOffPointer = new uint[] { 0 };
            for (int i = 0; i < _pArray.Length; i++)
            {
                _pArray[i] = _pArray[i] ^ StreamToWord(key, keyOffPointer);
            }
            for (int i = 0; i < _pArray.Length; i += 2)
            {
                lr[0] ^= StreamToWord(data, dataOffPointer);
                lr[1] ^= StreamToWord(data, dataOffPointer);
                Encipher(lr, 0);
                _pArray[i] = lr[0];
                _pArray[i + 1] = lr[1];
            }
            for (int i = 0; i < _sArray.Length; i += 2)
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
        /// <param name="key">An array containing the key.</param>
        void Key(byte[] key)
        {
            uint[] keyOffPointer = new uint[] { 0 };
            uint[] data = new uint[] { 0, 0 };
            for (int i = 0; i < _pArray.Length; i++)
            {
                _pArray[i] = _pArray[i] ^ StreamToWord(key, keyOffPointer);
            }
            for (int i = 0; i < _pArray.Length; i += 2)
            {
                Encipher(data, 0);
                _pArray[i] = data[0];
                _pArray[i + 1] = data[1];
            }
            for (int i = 0; i < _sArray.Length; i += 2)
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
            uint word = 0;
            uint off = offsetPointer[0];
            for (int i = 0; i < 4; i++)
            {
                word = (word << 8) | ((uint)data[off] & 0xff);
                off = (uint)((off + 1) % data.Length);
            }
            offsetPointer[0] = off;
            return word;
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
        public byte[] CryptRaw(byte[] password, byte[] salt, byte logRounds)
        {
            if (logRounds < Constants.MinLogRounds || logRounds > Constants.MaxLogRounds)
            {
                throw new ArgumentException("Bad number of rounds", nameof(logRounds));
            }
            if (salt.Length != Constants.SaltLength)
            {
                throw new ArgumentException("Bad salt length", nameof(salt));
            }
            EnhancedKeySchedule(salt, password);
            int rounds = 1 << logRounds;
            for (int i = 0; i < rounds; i++)
            {
                Key(password);
                Key(salt);
            }
            uint[] data = (uint[])BCryptArrays.BFCryptCiphertext.Clone();
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < (data.Length >> 1); j++)
                {
                    Encipher(data, (byte)(j << 1));
                }
            }
            byte[] cryptData = new byte[data.Length * 4];
            for (int i = 0, j = 0; i < data.Length; i++)
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