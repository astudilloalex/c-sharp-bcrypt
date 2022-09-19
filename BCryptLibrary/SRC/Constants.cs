namespace BCryptLibrary.SRC
{
    /// <summary>
    /// Contains the neccesary constants to use in BCrypt.
    /// </summary>
    internal class Constants
    {
        /// <summary>
        /// Default blowfish rounds.
        /// </summary>
        public static byte BlowfishRounds
        {
            get
            {
                return 16;
            }
        }

        /// <summary>
        /// Binary logarithm max number of rounds of hashing to apply.
        /// </summary>
        public static byte MaxLogRounds
        {
            get
            {
                return 31;
            }
        }

        /// <summary>
        /// Binary logarithm min number of rounds of hashing to apply.
        /// </summary>
        public static byte MinLogRounds
        {
            get
            {
                return 4;
            }
        }

        /// <summary>
        /// Default rounds of salt.
        /// </summary>
        public static byte SaltDefaultLogRounds
        {
            get
            {
                return 10;
            }
        }

        /// <summary>
        /// Default salt length.
        /// </summary>
        public static byte SaltLength
        {
            get
            {
                return 16;
            }
        }
    }
}