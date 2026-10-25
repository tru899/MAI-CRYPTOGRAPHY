public interface ISymmetricCipher
{
    int BlockSize { get; }
    byte[] Encrypt(byte[] block);

    byte[] Decrypt(byte[] block);

    void SetKey(byte[] key);
}
