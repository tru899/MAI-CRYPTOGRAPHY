using System.Diagnostics;
using System.Text;

string demo_dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
string files_dir = Path.Combine(demo_dir, "files");
string out_dir = Path.Combine(demo_dir, "out");
Directory.CreateDirectory(files_dir);
Directory.CreateDirectory(out_dir);

(string name, Func<ISymmetricCipher> create, byte[] key)[] all_ciphers =
[
    ("DES",      () => new Des(),  Convert.FromHexString("133457799BBCDFF1")),
    ("DEAL-128", () => new Deal(), Convert.FromHexString("00112233445566778899AABBCCDDEEFF")),
    ("DEAL-192", () => new Deal(), Convert.FromHexString("00112233445566778899AABBCCDDEEFF0011223344556677")),
    ("DEAL-256", () => new Deal(), Convert.FromHexString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")),
];

string cipher_arg = "default";
string mode_arg = "all";
string padding_arg = "PKCS7";
string? key_arg = null;
string? iv_arg = null;
long delta = 12345;
List<string> texts = [];
List<string> hexes = [];
List<string> paths = [];

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--cipher") cipher_arg = args[++i];
    else if (args[i] == "--mode") mode_arg = args[++i];
    else if (args[i] == "--padding") padding_arg = args[++i];
    else if (args[i] == "--key") key_arg = args[++i];
    else if (args[i] == "--iv") iv_arg = args[++i];
    else if (args[i] == "--delta") delta = long.Parse(args[++i]);
    else if (args[i] == "--text") texts.Add(args[++i]);
    else if (args[i] == "--hex") hexes.Add(args[++i]);
    else paths.Add(args[i]);
}

bool user_data = texts.Count > 0 || hexes.Count > 0 || paths.Count > 0;

(string name, Func<ISymmetricCipher> create, byte[] key)[] ciphers;
if (cipher_arg.Equals("all", StringComparison.OrdinalIgnoreCase))
{
    ciphers = all_ciphers;
}
else if (cipher_arg == "default")
{
    ciphers = user_data ? all_ciphers[..2] : all_ciphers;
}
else
{
    ciphers = [.. all_ciphers.Where(c => c.name.Equals(cipher_arg, StringComparison.OrdinalIgnoreCase))];
}
if (ciphers.Length == 0)
{
    Console.WriteLine($"нет шифра {cipher_arg}: можно DES, DEAL-128, DEAL-192, DEAL-256, all");
    return;
}

EncryptionMode[] modes;
if (mode_arg.Equals("all", StringComparison.OrdinalIgnoreCase))
{
    modes = Enum.GetValues<EncryptionMode>();
}
else if (Enum.TryParse(mode_arg, true, out EncryptionMode one_mode))
{
    modes = [one_mode];
}
else
{
    Console.WriteLine($"нет режима {mode_arg}: можно {string.Join(", ", Enum.GetNames<EncryptionMode>())}, all");
    return;
}

PaddingMode[] paddings;
if (padding_arg.Equals("all", StringComparison.OrdinalIgnoreCase))
{
    paddings = Enum.GetValues<PaddingMode>();
}
else if (Enum.TryParse(padding_arg, true, out PaddingMode one_padding))
{
    paddings = [one_padding];
}
else
{
    Console.WriteLine($"нет набивки {padding_arg}: можно {string.Join(", ", Enum.GetNames<PaddingMode>())}, all");
    return;
}

SymmetricCipher NewCipher(int index, EncryptionMode mode, PaddingMode padding, out byte[] key, out byte[] iv)
{
    ISymmetricCipher cipher = ciphers[index].create();
    key = key_arg == null ? ciphers[index].key : Convert.FromHexString(key_arg);
    if (iv_arg == null)
    {
        iv = new byte[cipher.BlockSize];
        Random.Shared.NextBytes(iv);
    }
    else
    {
        iv = Convert.FromHexString(iv_arg);
    }
    return new SymmetricCipher(key, mode, padding, cipher, iv, delta);
}

try
{
    await RunAll();
}
catch (Exception e) when (e is ArgumentException || e is FormatException || e is FileNotFoundException)
{
    Console.WriteLine($"ошибка: {e.Message}");
}

async Task RunAll()
{
    List<(string label, byte[] data, bool is_text)> inputs = [];
    foreach (string text in texts) inputs.Add(($"текст \"{text}\"", Encoding.UTF8.GetBytes(text), true));
    foreach (string hex in hexes) inputs.Add(($"байты {hex}", Convert.FromHexString(hex), false));

    foreach ((string label, byte[] data, bool is_text) in inputs)
    {
        Console.WriteLine($"\n=== {label}, {data.Length} байт ===");
        Console.WriteLine($"  открытый:       {Convert.ToHexString(data)}");
        for (int c = 0; c < ciphers.Length; c++)
        {
            foreach (EncryptionMode mode in modes)
            {
                foreach (PaddingMode padding in paddings)
                {
                    SymmetricCipher cipher = NewCipher(c, mode, padding, out byte[] key, out byte[] iv);
                    byte[] encrypted = cipher.Encrypt(data);
                    byte[] decrypted = cipher.Decrypt(encrypted);
                    bool ok = decrypted.AsSpan().SequenceEqual(data);
                    string as_text = is_text ? $"  \"{Encoding.UTF8.GetString(decrypted)}\"" : "";

                    Console.WriteLine($"\n  {ciphers[c].name} {mode} {padding}   ключ {Convert.ToHexString(key)}   IV {(mode == EncryptionMode.ECB ? "-" : Convert.ToHexString(iv))}");
                    Console.WriteLine($"  зашифрованный:  {Convert.ToHexString(encrypted)}");
                    Console.WriteLine($"  расшифрованный: {Convert.ToHexString(decrypted)}{as_text}  {(ok ? "OK" : "ОШИБКА")}");
                }
            }
        }
    }

    if (!user_data)
    {
        Console.WriteLine("=== Псевдослучайные последовательности: 10000 байт ===");
        byte[] random_data = new byte[10000];
        new Random(2026).NextBytes(random_data);

        for (int c = 0; c < ciphers.Length; c++)
        {
            foreach (EncryptionMode mode in modes)
            {
                foreach (PaddingMode padding in paddings)
                {
                    SymmetricCipher cipher = NewCipher(c, mode, padding, out _, out _);
                    Stopwatch watch = Stopwatch.StartNew();
                    byte[] encrypted = cipher.Encrypt(random_data);
                    byte[] decrypted = cipher.Decrypt(encrypted);
                    watch.Stop();

                    bool ok = decrypted.AsSpan().SequenceEqual(random_data);
                    Console.WriteLine($"  {ciphers[c].name,-9} {mode,-5} {padding,-9} {random_data.Length} -> {encrypted.Length} байт  {watch.ElapsedMilliseconds,5} мс  {(ok ? "OK" : "ОШИБКА")}");
                }
            }
        }
    }

    List<string> files = [];
    if (!user_data)
    {
        files.AddRange(Directory.EnumerateFiles(files_dir, "*", SearchOption.AllDirectories).Where(f => !Path.GetFileName(f).StartsWith('.')));
    }
    foreach (string path in paths)
    {
        if (File.Exists(path)) files.Add(path);
        else if (Directory.Exists(path)) files.AddRange(Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories));
        else Console.WriteLine($"нет такого файла или папки: {path}");
    }

    if (files.Count == 0)
    {
        if (!user_data) Console.WriteLine($"\nпапка {files_dir} пустая: положи туда файлы и запусти снова");
        return;
    }

    (string name, Func<ISymmetricCipher> create, byte[] key)[] file_ciphers = cipher_arg == "default" ? ciphers[..Math.Min(2, ciphers.Length)] : ciphers;
    Console.WriteLine("\n=== Файлы ===");

    foreach (string file in files)
    {
        Console.WriteLine($"\n  {Path.GetFileName(file)} — {new FileInfo(file).Length} байт");

        for (int c = 0; c < file_ciphers.Length; c++)
        {
            foreach (EncryptionMode mode in modes)
            {
                foreach (PaddingMode padding in paddings)
                {
                    string name = $"{Path.GetFileName(file)}.{file_ciphers[c].name}.{mode}.{padding}";
                    string encrypted_path = Path.Combine(out_dir, name + ".enc");
                    string decrypted_path = Path.Combine(out_dir, name + Path.GetExtension(file));
                    SymmetricCipher cipher = NewCipher(c, mode, padding, out _, out _);

                    Stopwatch watch = Stopwatch.StartNew();
                    await cipher.EncryptAsync(file, encrypted_path);
                    await cipher.DecryptAsync(encrypted_path, decrypted_path);
                    watch.Stop();

                    bool ok = FilesEqual(file, decrypted_path);
                    Console.WriteLine($"    {file_ciphers[c].name,-9} {mode,-5} {padding,-9} {watch.ElapsedMilliseconds,6} мс  {(ok ? "OK" : "ОШИБКА")}");
                }
            }
        }
    }

    Console.WriteLine($"\nРезультаты: {out_dir}");
}

static bool FilesEqual(string first_path, string second_path)
{
    using FileStream first = File.OpenRead(first_path);
    using FileStream second = File.OpenRead(second_path);
    if (first.Length != second.Length) return false;

    byte[] first_buffer = new byte[1 << 20];
    byte[] second_buffer = new byte[1 << 20];
    int read;
    while ((read = first.ReadAtLeast(first_buffer, first_buffer.Length, throwOnEndOfStream: false)) > 0)
    {
        second.ReadExactly(second_buffer, 0, read);
        if (!first_buffer.AsSpan(0, read).SequenceEqual(second_buffer.AsSpan(0, read))) return false;
    }
    return true;
}
