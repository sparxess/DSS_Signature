using System;
using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Nethereum.Util;
using Nethereum.Signer.Crypto;

class Frolov_DSS
{
    static void Main()
    {
        //создание ключа
        //var privKey = EthECKey.GenerateKey(); // случайный ключ
        var privKey = new EthECKey("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a");
        
        //byte[] pubKeyCompressed = new ECKey(privKey.GetPrivateKeyAsBytes(), true).GetPubKey(true);
        //Console.WriteLine("Private key: {0}", privKey.GetPrivateKey().Substring(4));
        //Console.WriteLine("Public key: {0}", privKey.GetPubKey().ToHex().Substring(2));
        //Console.WriteLine("Public key (compressed): {0}", pubKeyCompressed.ToHex());
        
        Console.WriteLine();

        //Добавление файла с собощением
        Console.WriteLine("Введите файл, содержащий сообщение: ");
        string path = Console.ReadLine();
        string msg = readFile(path);
        //string msg = "Message for signing";

        //создание подписи на основе хэша 
        byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
        byte[] msgHash = new Sha3Keccack().CalculateHash(msgBytes);
        var signature = privKey.SignAndCalculateV(msgHash);

        //Console.WriteLine("Msg: {0}", msg);
        //Console.WriteLine("Msg hash: {0}", msgHash.ToHex());
        //Console.WriteLine("Signature: [v = {0}, r = {1}, s = {2}]",
        //    signature.V[0] - 27, signature.R.ToHex(), signature.S.ToHex());
        //Console.WriteLine($"Signature: {signature.R.ToHex()}{signature.S.ToHex()}");

        Console.WriteLine();

        //Вывод ЭЦП в отдельный файл
        Console.WriteLine("Введите файл для сохранения ЭЦП: ");
        path = Console.ReadLine();
        string sign = $"ЭЦП: {signature.R.ToHex()}{signature.S.ToHex()}";
        writeFile(path, sign);
        Console.WriteLine();

        //Верификация

        Console.WriteLine("Выберите файл для верификации сообщения: ");
        path = Console.ReadLine();
        string msg2 = readFile(path);
        Console.WriteLine();
        byte[] msgBytes2 = Encoding.UTF8.GetBytes(msg2);
        byte[] msgHash2 = new Sha3Keccack().CalculateHash(msgBytes2);
        var signature2 = privKey.SignAndCalculateV(msgHash);
        //string signVer = $"ЭЦП: {signature2.R.ToHex()}{signature2.S.ToHex()}";
        //Console.WriteLine($"ЭЦП: {signature2.R.ToHex()}{signature2.S.ToHex()}");

        var pubKeyRecovered = EthECKey.RecoverFromSignature(signature2, msgHash2);
        //Console.WriteLine("Recovered pubKey: {0}", pubKeyRecovered.GetPubKey().ToHex().Substring(2));

        bool validSig = pubKeyRecovered.Verify(msgHash, signature);
        if (validSig)
            Console.WriteLine("Верификация прошла успешно.Цифровая подпись верна.");
        else
            Console.WriteLine("Верификация не прошла! Цифровая подпись не верна.");

        Console.WriteLine("Содержимое исходного файла: ");
        Console.WriteLine();
        Console.WriteLine(msg2);



        Console.ReadKey();
    }

    private static string readFile(string path)
    {
        string text = System.IO.File.ReadAllText(path);
        return (text);
    }

    private static void writeFile(string path, string text)
    {
        System.IO.File.WriteAllText(path, text);
    }
}
