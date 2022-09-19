// See https://aka.ms/new-console-template for more information

using BCryptLibrary;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Test");
        Console.WriteLine(BCrypt.HashPassword("password", BCrypt.GenSalt()));
    }
}
