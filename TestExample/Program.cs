// See https://aka.ms/new-console-template for more information
using BCryptLibrary;

Console.WriteLine(BCrypt.HashPassword("alexastudillo", BCrypt.GenSalt()));
Console.WriteLine(BCrypt.CheckPassword("alexastudillo", "$2a$10$CLJONHsMxz3Xx05Z2gT56eKDlG.A7ThpzqHoZ66ni4yfDVdaI0Haq"));
