public interface ICipherTransform
{
    byte[] Transform(byte[] block, byte[] roundKey);
}
