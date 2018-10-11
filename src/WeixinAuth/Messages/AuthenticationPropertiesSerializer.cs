using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth
{
    /// <summary>
    /// Serializes and deserializes WeixinAuth request and access tokens so that they can be used by other application components.
    /// </summary>
    public class WeixinAuthenticationPropertiesSerializer : IDataSerializer<AuthenticationProperties>
    {
        private const int FormatVersion = 2;

        /// <summary>
        /// Serialize a request token.
        /// </summary>
        /// <param name="model">The token to serialize</param>
        /// <returns>A byte array containing the serialized token</returns>
        public virtual byte[] Serialize(AuthenticationProperties model)
        {
            var s = JsonConvert.SerializeObject(model.Items, Formatting.None);

            var r = Encoding.UTF8.GetBytes(s);
            var r1 = Zipper.Zip(s);
            var r2 = CompressionExtensions.Zip(s).Result.ToArray();
            return r;
        }


        /// <summary>
        /// Deserializes a request token.
        /// </summary>
        /// <param name="data">A byte array containing the serialized token</param>
        /// <returns>The Twitter request token</returns>
        public virtual AuthenticationProperties Deserialize(byte[] data)
        {
            var s = Zipper.Unzip(data);

            var items = JsonConvert.DeserializeObject<IDictionary<string, string>>(s);
            return new AuthenticationProperties(items);
        }

        /// <summary>
        /// Writes a Twitter request token as a series of bytes. Used by the <see cref="Serialize"/> method.
        /// </summary>
        /// <param name="writer">The writer to use in writing the token</param>
        /// <param name="token">The token to write</param>
        public static void Write(BinaryWriter writer, AuthenticationProperties token)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            writer.Write(FormatVersion);
            PropertiesSerializer.Default.Write(writer, token);
        }

        /// <summary>
        /// Reads a Twitter request token from a series of bytes. Used by the <see cref="Deserialize"/> method.
        /// </summary>
        /// <param name="reader">The reader to use in reading the token bytes</param>
        /// <returns>The token</returns>
        public static AuthenticationProperties Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }

            AuthenticationProperties properties = PropertiesSerializer.Default.Read(reader);
            if (properties == null)
            {
                return null;
            }

            return properties;
        }
    }
}
