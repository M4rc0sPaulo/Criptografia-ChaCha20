using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Program
{
    static void Main()
    {
        // Dados para criptografar
        string plaintext = "Hello, ChaCha20!";
        byte[] input = System.Text.Encoding.UTF8.GetBytes(plaintext);

        // Chave secreta (deve ser mantida em segredo)
        byte[] key = new byte[32]; // 256 bits
        SecureRandom random = new SecureRandom();
        random.NextBytes(key);

        // Vetor de inicialização (IV)
        byte[] iv = new byte[12]; // 96 bits
        random.NextBytes(iv);

        // Configurar o ChaCha20
        IStreamCipher cipher = new ChaCha7539Engine();
        KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("ChaCha", key);
        ParametersWithIV parameters = new ParametersWithIV(keyParam, iv);
        cipher.Init(true, parameters);

        // Criptografar
        byte[] ciphertext = new byte[input.Length];
        cipher.ProcessBytes(input, 0, input.Length, ciphertext, 0);

        // Exibir resultados
        Console.WriteLine("Texto Original: " + plaintext);
        Console.WriteLine("Chave: " + BitConverter.ToString(key).Replace("-", ""));
        Console.WriteLine("IV: " + BitConverter.ToString(iv).Replace("-", ""));
        Console.WriteLine("Texto Criptografado: " + BitConverter.ToString(ciphertext).Replace("-", ""));

        // Descriptografar
        cipher.Reset();
        cipher.Init(false, parameters);
        byte[] decrypted = new byte[ciphertext.Length];
        cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, decrypted, 0);
        string decryptedText = System.Text.Encoding.UTF8.GetString(decrypted);

        Console.WriteLine("Texto Descriptografado: " + decryptedText);
    }
}
