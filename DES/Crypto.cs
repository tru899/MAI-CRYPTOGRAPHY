public enum EncryptionMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RD
}


public enum PaddingMode {
    ZEROS,
    ANSIX923,
    PKCS7,
    ISO10126    
}


public class SymmetricCipher
{
    private EncryptionMode encrypt_mode;
    private PaddingMode pad_mode;
    private ISymmetricCipher cipher_text;
    private byte[]? initial_vector;
    private object[] param;

    public SymmetricCipher(byte[] keys, EncryptionMode encrypt_mode, PaddingMode pad_mode, ISymmetricCipher cipher_text, byte[]? initial_vector = null, params object[] param)
    {
        if (keys == null) throw new ArgumentNullException(nameof(keys));
        if (cipher_text == null) throw new ArgumentNullException(nameof(cipher_text));
        if (!Enum.IsDefined(encrypt_mode)) throw new ArgumentException("unknown encryption mode");
        if (!Enum.IsDefined(pad_mode)) throw new ArgumentException("unknown padding mode");

        this.encrypt_mode = encrypt_mode;
        this.pad_mode = pad_mode;
        this.initial_vector = initial_vector;
        this.cipher_text = cipher_text;
        this.param = param ?? [];
        cipher_text.SetKey(keys);

        if (initial_vector != null && initial_vector.Length != cipher_text.BlockSize)
        {
            throw new ArgumentException("initial vector length must be equal to block size");
        }

        if (encrypt_mode != EncryptionMode.ECB && initial_vector == null)
        {
            throw new ArgumentException("initial vector is null");
        }

        if (encrypt_mode == EncryptionMode.RD)
        {
            if (this.param.Length == 0) throw new ArgumentException("RD needs delta in params");

            long delta;
            try
            {
                delta = Convert.ToInt64(this.param[0]);
            }
            catch (Exception)
            {
                throw new ArgumentException("delta must be an integer");
            }

            if (delta <= 0 || delta % 2 == 0) throw new ArgumentException("delta must be positive and odd");
        }
    }


    // FOR PADDING
    int GetPaddingLength(int dataLength, int blockSize)
    {
        int padding_len = blockSize - dataLength % blockSize;
        if (pad_mode == PaddingMode.ZEROS && padding_len == blockSize)
        {
            return 0;
        }
        return padding_len;
    }

    byte[] AddPadding(byte[] data, int blockSize)
    {
        int padding_len = GetPaddingLength(data.Length, blockSize);
        
        byte[] res = new byte[data.Length + padding_len];
        data.CopyTo(res, 0);
        
        if (pad_mode == PaddingMode.ZEROS)
        {
            return res;
        }

        else if (pad_mode == PaddingMode.ANSIX923)
        {
            res[res.Length - 1] = (byte)padding_len;
        }

        else if (pad_mode == PaddingMode.PKCS7)
        {
            for (int i = data.Length; i < res.Length; i++)
            {
                res[i] = (byte)padding_len;
            }
        }

        else if (pad_mode == PaddingMode.ISO10126)
        {
            for (int i = data.Length; i < res.Length; i++)
            {
                res[i] = (byte)Random.Shared.Next(256);
            }

            res[res.Length - 1] = (byte)padding_len;
        }
        return res;
    }

    byte[] RemovePadding(byte[] data, int blockSize)
    {   
        if (data.Length == 0) { return data; }

        if (pad_mode == PaddingMode.ZEROS)
        {
            int last = data.Length;
            while (last > 0 && data[last - 1] == 0 && data.Length - last < blockSize - 1)
            {
                last--;
            }
            return data[..last];
        }

        int n = data[data.Length - 1];
        if (n < 1 || n > blockSize || n > data.Length)
        {
            throw new ArgumentException("invalid padding");
        }

        for (int i = data.Length - n; i < data.Length - 1; i++)
        {
            if (pad_mode == PaddingMode.PKCS7 && data[i] != n) throw new ArgumentException("invalid padding");
            if (pad_mode == PaddingMode.ANSIX923 && data[i] != 0) throw new ArgumentException("invalid padding");
        }

        return data[..^n];
    }


    // HELPERS
    public static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] res = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            res[i] = (byte)(a[i] ^ b[i]);
        }
        return res;
    }

    private static void Add(byte[] ctr, long delta)
    {
        for (int i = ctr.Length - 1; i >= 0 && delta != 0; i--)
        {
            long sum = ctr[i] + (delta & 0xFF);
            ctr[i] = (byte)sum;
            delta = (delta >> 8) + (sum >> 8);
        }
    }

    private byte[]? chain;
    private byte[]? chain_block;
    private long block_index;

    private void ResetState()
    {
        chain = initial_vector;
        chain_block = new byte[cipher_text.BlockSize];
        block_index = 0;
    }


    // ENCRYPT
    public byte[] Encrypt(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        ResetState();
        return EncryptChunk(data, true);
    }

    private byte[] EncryptChunk(byte[] data, bool is_last)
    {
        if (is_last && (encrypt_mode == EncryptionMode.ECB 
            || encrypt_mode == EncryptionMode.CBC 
            || encrypt_mode == EncryptionMode.PCBC))
        {
            data = AddPadding(data, cipher_text.BlockSize);
        }

        if (encrypt_mode == EncryptionMode.ECB)
        {
            return EncryptECB(data);
        }
        else if (encrypt_mode == EncryptionMode.CBC)
        {
            return EncryptCBC(data);
        }
        else if (encrypt_mode == EncryptionMode.PCBC)
        {
            return EncryptPCBC(data);
        }
        else if (encrypt_mode == EncryptionMode.CFB)
        {
            return EncryptCFB(data);
        }
        else if (encrypt_mode == EncryptionMode.OFB)
        {
            return EncryptOFB(data);
        }
        else if (encrypt_mode == EncryptionMode.CTR)
        {
            return EncryptCTR(data);
        }
        else if (encrypt_mode == EncryptionMode.RD)
        {
            return EncryptRD(data);
        }

        throw new NotImplementedException("mode isn't available");
    }

    private byte[] EncryptECB(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];

        Parallel.For(0, blocks, i =>
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] encrypted = cipher_text.Encrypt(block);
            encrypted.CopyTo(res, i * block_size);
        });
        return res;
    }

    private byte[] EncryptCBC(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = chain;
        if (prev == null) throw new ArgumentException("initial vector is null");

        for (int i = 0; i < blocks; i++)
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] encrypted = cipher_text.Encrypt(Xor(block, prev));
            prev = encrypted;
            encrypted.CopyTo(res, i * block_size);
        }
        chain = prev;
        return res;
    }

    private byte[] EncryptPCBC(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = chain;
        if (prev == null) throw new ArgumentException("initial vector is null");

        byte[] prev_block = chain_block;

        for (int i = 0; i < blocks; i++)
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] encrypted = cipher_text.Encrypt(Xor(Xor(block, prev_block), prev));
            prev = encrypted;
            prev_block = block;
            encrypted.CopyTo(res, i * block_size);
        }
        chain = prev;
        chain_block = prev_block;
        return res;
    }

    private byte[] EncryptCFB(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = (data.Length + block_size - 1) / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = chain;
        if (prev == null) throw new ArgumentException("initial vector is null");

        for (int i = 0; i < blocks; i++)
        {
            int last = Math.Min((i + 1) * block_size, data.Length);
            byte[] block = data[(i * block_size)..last];
            byte[] encrypted = Xor(block, cipher_text.Encrypt(prev));
            prev = encrypted;
            encrypted.CopyTo(res, i * block_size);
        }
        chain = prev;
        return res;
    }

    private byte[] EncryptOFB(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = (data.Length + block_size - 1) / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = chain;
        if (prev == null) throw new ArgumentException("initial vector is null");

        for (int i = 0; i < blocks; i++)
        {
            int last = Math.Min((i + 1) * block_size, data.Length);
            byte[] block = data[(i * block_size)..last];
            byte[] oi = cipher_text.Encrypt(prev);
            byte[] encrypted = Xor(block, oi);
            prev = oi;
            encrypted.CopyTo(res, i * block_size);
        }
        chain = prev;
        return res;
    }

    private byte[] EncryptCTR(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = (data.Length + block_size - 1) / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = initial_vector;
        if (prev == null) throw new ArgumentException("initial vector is null");
        
        long start = block_index;

        Parallel.For(0, blocks, i =>
        {
            int last = Math.Min((i + 1) * block_size, data.Length);
            byte[] block = data[(i * block_size)..last];
            byte[] ctr = (byte[])prev.Clone();
            Add(ctr, start + i);

            byte[] ctr_encrypted = cipher_text.Encrypt(ctr);
            byte[] encrypted = Xor(block, ctr_encrypted);
            encrypted.CopyTo(res, i * block_size);
        });
        block_index += blocks;
        return res;
    }

    private byte[] EncryptRD(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = (data.Length + block_size - 1) / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = initial_vector;
        if (prev == null) throw new ArgumentException("initial vector is null");

        if (param.Length == 0) throw new ArgumentException("RD needs delta in params");
        long delta = Convert.ToInt64(param[0]);
        if (delta <= 0 || delta % 2 == 0) throw new ArgumentException("delta must be positive and odd");

        long start = block_index;

        Parallel.For(0, blocks, i =>
        {
            int last = Math.Min((i + 1) * block_size, data.Length);
            byte[] block = data[(i * block_size)..last];
            byte[] ctr = (byte[])prev.Clone();
            Add(ctr, (start + i) * delta);

            byte[] ctr_encrypted = cipher_text.Encrypt(ctr);
            byte[] encrypted = Xor(block, ctr_encrypted);
            encrypted.CopyTo(res, i * block_size);
        });
        block_index += blocks;
        return res;
    }


    // DECRYPT
    public byte[] Decrypt(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        ResetState();
        return DecryptChunk(data, true);
    }
    
    private byte[] DecryptChunk(byte[] data, bool is_last)
    {
        int block_size = cipher_text.BlockSize;

        if (encrypt_mode == EncryptionMode.ECB 
            || encrypt_mode == EncryptionMode.CBC 
            || encrypt_mode == EncryptionMode.PCBC)
        {
            if (data.Length % block_size != 0)
            {
                throw new ArgumentException("ciphertext length must be a multiple of block size");
            }
        }

        if (encrypt_mode == EncryptionMode.ECB)
        {
            byte[] res = DecryptECB(data);
            return is_last ? RemovePadding(res, block_size) : res;
        }
        else if (encrypt_mode == EncryptionMode.CBC)
        {
            byte[] res = DecryptCBC(data);
            return is_last ? RemovePadding(res, block_size) : res;
        }
        else if (encrypt_mode == EncryptionMode.PCBC)
        {
            byte[] res = DecryptPCBC(data);
            return is_last ? RemovePadding(res, block_size) : res;
        }
        else if (encrypt_mode == EncryptionMode.CFB)
        {
            return DecryptCFB(data);
        }
        else if (encrypt_mode == EncryptionMode.OFB)
        {
            return DecryptOFB(data);
        }
        else if (encrypt_mode == EncryptionMode.CTR)
        {
            return DecryptCTR(data);
        }
        else if (encrypt_mode == EncryptionMode.RD)
        {
            return DecryptRD(data);
        }

        throw new NotImplementedException("mode isn't available");
    }

    private byte[] DecryptECB(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];

        Parallel.For(0, blocks, i =>
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] decrypted = cipher_text.Decrypt(block);
            decrypted.CopyTo(res, i * block_size);
        });
        return res;
    }

    private byte[] DecryptCBC(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];

        byte[] prev_iv = chain;
        if (prev_iv == null) throw new ArgumentException("initial vector is null");

        Parallel.For(0, blocks, i =>
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] prev = (i == 0) ? prev_iv : data[((i - 1) * block_size)..(i * block_size)];
            byte[] decrypted = Xor(cipher_text.Decrypt(block), prev);
            decrypted.CopyTo(res, i * block_size);
        });

        if (blocks > 0)
        {
            chain = data[((blocks - 1) * block_size)..(blocks * block_size)];
        }
        return res;
    }

    private byte[] DecryptPCBC(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = data.Length / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev = chain;
        if (prev == null) throw new ArgumentException("initial vector is null");

        byte[] prev_block = chain_block;
        
        for (int i = 0; i < blocks; i++)
        {
            byte[] block = data[(i * block_size)..((i + 1) * block_size)];
            byte[] decrypted = Xor(Xor(cipher_text.Decrypt(block), prev), prev_block);
            prev = block;
            prev_block = decrypted;
            decrypted.CopyTo(res, i * block_size);
        }

        chain = prev;
        chain_block = prev_block;

        return res;
    }

    private byte[] DecryptCFB(byte[] data)
    {
        int block_size = cipher_text.BlockSize;
        int blocks = (data.Length + block_size - 1) / block_size;
        byte[] res = new byte[data.Length];
        
        byte[] prev_iv = chain;
        if (prev_iv == null) throw new ArgumentException("initial vector is null");

        Parallel.For(0, blocks, i =>
        {
            int last = Math.Min((i + 1) * block_size, data.Length);
            byte[] block = data[(i * block_size)..last];
            byte[] prev = (i == 0) ? prev_iv : data[((i - 1) * block_size)..(i * block_size)];
            byte[] decrypted = Xor(block, cipher_text.Encrypt(prev));
            decrypted.CopyTo(res, i * block_size);
        });

        if (blocks > 0 && data.Length % block_size == 0)
        {
            chain = data[((blocks - 1) * block_size)..(blocks * block_size)];
        }
        return res;
    }

    private byte[] DecryptOFB(byte[] data)
    {
        return EncryptOFB(data);
    }

    private byte[] DecryptCTR(byte[] data)
    {
        return EncryptCTR(data);
    }

    private byte[] DecryptRD(byte[] data)
    {
        return EncryptRD(data);
    }


    // ASYNC
    public Task<byte[]> EncryptAsync(byte[] data)
    {
        return Task.Run(() => Encrypt(data));
    }

    public Task<byte[]> DecryptAsync(byte[] data)
    {
        return Task.Run(() => Decrypt(data));
    }


    // FILES
    private const int CHUNK_BLOCKS = 65536;

    private static void CheckPaths(string input_path, string output_path)
    {
        if (string.IsNullOrWhiteSpace(input_path)) throw new ArgumentException("input path is empty");
        if (string.IsNullOrWhiteSpace(output_path)) throw new ArgumentException("output path is empty");
        if (!File.Exists(input_path)) throw new FileNotFoundException("input file not found", input_path);
        if (Path.GetFullPath(input_path) == Path.GetFullPath(output_path)) throw new ArgumentException("output file must differ from input file");
    }
    private static async Task<byte[]> ReadChunk(FileStream input, int size)
    {
        byte[] buffer = new byte[size];
        int read = await input.ReadAtLeastAsync(buffer, size, throwOnEndOfStream: false);
        return buffer[..read];
    }

    public async Task EncryptAsync(string input_path, string output_path)
    {
        CheckPaths(input_path, output_path);
        ResetState();
        int chunk_size = cipher_text.BlockSize * CHUNK_BLOCKS;

        using FileStream input = File.OpenRead(input_path);
        using FileStream output = File.Create(output_path);

        byte[] current = await ReadChunk(input, chunk_size);
        while (true)
        {
            byte[] next = await ReadChunk(input, chunk_size);
            bool is_last = next.Length == 0;

            byte[] encrypted = EncryptChunk(current, is_last);
            await output.WriteAsync(encrypted);

            if (is_last) { break; }
            current = next;
        }
    }

    public async Task DecryptAsync(string input_path, string output_path)
    {
        CheckPaths(input_path, output_path);
        ResetState();
        int chunk_size = cipher_text.BlockSize * CHUNK_BLOCKS;

        using FileStream input = File.OpenRead(input_path);
        using FileStream output = File.Create(output_path);

        byte[] current = await ReadChunk(input, chunk_size);
        while (true)
        {
            byte[] next = await ReadChunk(input, chunk_size);
            bool is_last = next.Length == 0;

            byte[] encrypted = DecryptChunk(current, is_last);
            await output.WriteAsync(encrypted);

            if (is_last) { break; }
            current = next;
        }
    }
}