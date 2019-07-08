using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuth451
{
    public static class EncryptHelper
    {
        #region prop

        /// <summary>
        /// 默认编码
        /// </summary>
        public static Encoding DefaultEncoding { get; } = Encoding.UTF8;
        //private static readonly string DefaultKey = "DefaultKey";
        #endregion prop

        #region 通用加密算法

        /// <summary>
        /// 哈希加密算法
        /// </summary>
        /// <param name="hashAlgorithm"> 所有加密哈希算法实现均必须从中派生的基类 </param>
        /// <param name="input"> 待加密的字符串 </param>
        /// <param name="encoding"> 字符编码，为 null 时采用默认编码（UTF-8） </param>
        /// <returns></returns>
        private static string HashEncrypt(HashAlgorithm hashAlgorithm, string input, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            var data = hashAlgorithm.ComputeHash(encoding.GetBytes(input));

            return BitConverter.ToString(data).Replace("-", "");
        }

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="hashAlgorithm"> 所有加密哈希算法实现均必须从中派生的基类 </param>
        /// <param name="unhashedText"> 未加密的字符串 </param>
        /// <param name="hashedText"> 经过加密的哈希值 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        private static bool VerifyHashValue(HashAlgorithm hashAlgorithm, string unhashedText, string hashedText,
            Encoding encoding = null)
        {
            return string.Equals(HashEncrypt(hashAlgorithm, unhashedText, encoding), hashedText,
                StringComparison.OrdinalIgnoreCase);
        }

        #endregion 通用加密算法

        #region 哈希加密算法

        #region MD5 算法

        /// <summary>
        /// MD5 加密
        /// </summary>
        /// <param name="input"> 待加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string Md5Encrypt(string input, Encoding encoding = null)
        {
            return HashEncrypt(MD5.Create(), input, encoding);
        }

        /// <summary>
        /// 验证 MD5 值
        /// </summary>
        /// <param name="input"> 未加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static bool VerifyMd5Value(string input, Encoding encoding = null)
        {
            return VerifyHashValue(MD5.Create(), input, Md5Encrypt(input, encoding), encoding);
        }

        #endregion MD5 算法

        #region SHA1 算法

        /// <summary>
        /// SHA1 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="encoding"> 字符编码，为 null 时取默认值 </param>
        /// <returns></returns>
        public static string Sha1Encrypt(string input, Encoding encoding = null)
        {
            return HashEncrypt(SHA1.Create(), input, encoding);
        }

        /// <summary>
        /// 验证 SHA1 值
        /// </summary>
        /// <param name="input"> 未加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static bool VerifySha1Value(string input, Encoding encoding = null)
        {
            return VerifyHashValue(SHA1.Create(), input, Sha1Encrypt(input, encoding), encoding);
        }

        #endregion SHA1 算法

        #region SHA256 算法

        /// <summary>
        /// SHA256 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string Sha256Encrypt(string input, Encoding encoding = null)
        {
            return HashEncrypt(SHA256.Create(), input, encoding);
        }

        /// <summary>
        /// 验证 SHA256 值
        /// </summary>
        /// <param name="input"> 未加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static bool VerifySha256Value(string input, Encoding encoding = null)
        {
            return VerifyHashValue(SHA256.Create(), input, Sha256Encrypt(input, encoding), encoding);
        }

        #endregion SHA256 算法

        #region SHA384 算法

        /// <summary>
        /// SHA384 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string Sha384Encrypt(string input, Encoding encoding = null)
        {
            return HashEncrypt(SHA384.Create(), input, encoding);
        }

        /// <summary>
        /// 验证 SHA384 值
        /// </summary>
        /// <param name="input"> 未加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static bool VerifySha384Value(string input, Encoding encoding = null)
        {
            return VerifyHashValue(SHA256.Create(), input, Sha384Encrypt(input, encoding), encoding);
        }

        #endregion SHA384 算法

        #region SHA512 算法

        /// <summary>
        /// SHA512 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string Sha512Encrypt(string input, Encoding encoding = null)
        {
            return HashEncrypt(SHA512.Create(), input, encoding);
        }

        /// <summary>
        /// 验证 SHA512 值
        /// </summary>
        /// <param name="input"> 未加密的字符串 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static bool VerifySha512Value(string input, Encoding encoding = null)
        {
            return VerifyHashValue(SHA512.Create(), input, Sha512Encrypt(input, encoding), encoding);
        }

        #endregion SHA512 算法

        #region HMAC-MD5 加密

        /// <summary>
        /// HMAC-MD5 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="key"> 密钥 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string HmacMd5Encrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return HashEncrypt(new HMACMD5(encoding.GetBytes(key)), input, encoding);
        }

        #endregion HMAC-MD5 加密

        #region HMAC-SHA1 加密

        /// <summary>
        /// HMAC-SHA1 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="key"> 密钥 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string HmacSha1Encrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return HashEncrypt(new HMACSHA1(encoding.GetBytes(key)), input, encoding);
        }

        #endregion HMAC-SHA1 加密

        #region HMAC-SHA256 加密

        /// <summary>
        /// HMAC-SHA256 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="key"> 密钥 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string HmacSha256Encrypt(string input, string key, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = DefaultEncoding;

            return HashEncrypt(new HMACSHA256(encoding.GetBytes(key)), input, encoding);
        }

        #endregion HMAC-SHA256 加密

        #region HMAC-SHA384 加密

        /// <summary>
        /// HMAC-SHA384 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="key"> 密钥 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string HmacSha384Encrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return HashEncrypt(new HMACSHA384(encoding.GetBytes(key)), input, encoding);
        }

        #endregion HMAC-SHA384 加密

        #region HMAC-SHA512 加密

        /// <summary>
        /// HMAC-SHA512 加密
        /// </summary>
        /// <param name="input"> 要加密的字符串 </param>
        /// <param name="key"> 密钥 </param>
        /// <param name="encoding"> 字符编码 </param>
        /// <returns></returns>
        public static string HmacSha512Encrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;
            return HashEncrypt(new HMACSHA512(encoding.GetBytes(key)), input, encoding);
        }

        #endregion HMAC-SHA512 加密

        #endregion 哈希加密算法

        #region 对称加密算法

        #region Des 加解密

        /// <summary>
        /// DES 加密
        /// </summary>
        /// <param name="input"> 待加密的字符串 </param>
        /// <param name="key"> 密钥（8位） </param>
        /// <param name="encoding">编码，为 null 取默认值</param>
        /// <returns></returns>
        public static string DesEncrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;

            try
            {

                var keyBytes = encoding.GetBytes(key);
                //var ivBytes = Encoding.UTF8.GetBytes(iv);

                var des = DES.Create();
                des.Mode = CipherMode.ECB; //兼容其他语言的 Des 加密算法
               // des.Padding = PaddingMode.Zeros; //自动补 0

                using (var ms = new MemoryStream())
                {
                    var data = encoding.GetBytes(input);
                    byte[] ivBytes = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

                    using (var cs =
                        new CryptoStream(ms, des.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
            catch
            {
                return input;
            }
        }

        /// <summary>
        /// DES 解密
        /// </summary>
        /// <param name="input"> 待解密的字符串 </param>
        /// <param name="key"> 密钥（8位） </param>
        /// <param name="encoding">编码，为 null 时取默认值</param>
        /// <returns></returns>
        public static string DesDecrypt(string input, string key, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;

            try
            {
                var keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] ivBytes = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

                var des = DES.Create();
                des.Mode = CipherMode.ECB; //兼容其他语言的Des加密算法
               // des.Padding = PaddingMode.Zeros; //自动补0

                using (var ms = new MemoryStream())
                {
                    var data = Convert.FromBase64String(input);

                    using (var cs =
                        new CryptoStream(ms, des.CreateDecryptor(keyBytes, ivBytes), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }

                    return encoding.GetString(ms.ToArray());
                }
            }
            catch
            {
                return input;
            }
        }

        #endregion Des 加解密

        #endregion 对称加密算法

        #region 非对称加密算法

        /// <summary>
        /// 生成 RSA 公钥和私钥
        /// </summary>
        /// <param name="publicKey"> 公钥 </param>
        /// <param name="privateKey"> 私钥 </param>
        public static void GenerateRsaKeys(out string publicKey, out string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);
            }
        }

        /// <summary>
        /// RSA 加密
        /// </summary>
        /// <param name="publickey"> 公钥 </param>
        /// <param name="content"> 待加密的内容 </param>
        /// <param name="encoding">编码，为 null 时取默认编码</param>
        /// <returns> 经过加密的字符串 </returns>
        public static string RsaEncrypt(string publickey, string content, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;

            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publickey);

            var cipherbytes = rsa.Encrypt(encoding.GetBytes(content), false);

            return Convert.ToBase64String(cipherbytes);
        }

        /// <summary>
        /// RSA 解密
        /// </summary>
        /// <param name="privatekey"> 私钥 </param>
        /// <param name="content"> 待解密的内容 </param>
        /// <param name="encoding"></param>
        /// <returns> 解密后的字符串 </returns>
        public static string RsaDecrypt(string privatekey, string content, Encoding encoding = null)
        {
            encoding = encoding ?? DefaultEncoding;

            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privatekey);
            var cipherbytes = rsa.Decrypt(Convert.FromBase64String(content), false);

            return encoding.GetString(cipherbytes);
        }

        #endregion 非对称加密算法


        /// <summary>
        /// 
        /// </summary>
        /// <param name="password">明文密码</param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public static string Encrypt(string password, string secretKey)
        {
            string ret = EncryptMD5Password(password.ToMD5(), secretKey);
            return ret;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="md5Password">经过md5加密的密码</param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public static string EncryptMD5Password(string md5Password, string secretKey)
        {
            secretKey = secretKey.ToMD5().Substring(0, 16);
            string encryptedPassword = EncryptHelper.AESEncrypt(md5Password.ToLower(), secretKey).ToLower();
            string ret = encryptedPassword.ToMD5().ToLower();
            return ret;
        }
        /// <summary>
        /// 使用 Encoding.UTF8 对 s 加密
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static string ToMD5(this string s)
        {
            return ToMD5(s, Encoding.UTF8);
        }
        /// <summary>
        /// md5
        /// </summary>
        /// <param name="s"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string ToMD5(this string s, Encoding encoding)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                var inputBytes = encoding.GetBytes(s);
                var hashBytes = md5.ComputeHash(inputBytes);

                var sb = new StringBuilder();
                foreach (var hashByte in hashBytes)
                {
                    sb.Append(hashByte.ToString("X2"));
                }

                return sb.ToString();
            }
        }
        /// <returns></returns>
        public static string AESEncrypt(string text, string key)
        {
            byte[] encryptKey = Encoding.UTF8.GetBytes(key);

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = encryptKey;
                aesAlg.IV = encryptKey;
                using (var encryptor = aesAlg.CreateEncryptor())
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(text);
                            }

                            var iv = aesAlg.IV;

                            var decryptedContent = msEncrypt.ToArray();

                            var result = new byte[iv.Length + decryptedContent.Length];

                            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                            Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                            return Convert.ToBase64String(result);
                        }
                    }
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <param name="key">长度必须是 16</param>
        /// <returns></returns>
        public static string AESDecrypt(string encryptedText, string key)
        {
            var fullCipher = Convert.FromBase64String(encryptedText);

            byte[] iv = new byte[16];

            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var decryptKey = Encoding.UTF8.GetBytes(key);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(decryptKey, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }

    }


}
