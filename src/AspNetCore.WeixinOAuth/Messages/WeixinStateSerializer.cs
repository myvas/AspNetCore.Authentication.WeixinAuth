using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Messages
{
    /// <summary>
    /// Serializes and deserializes WeixinOAuth request and access tokens so that they can be used by other application components.
    /// </summary>
    public class WeixinStateSerializer : IDataSerializer<WeixinState>
    {
        private const int FormatVersion = 1;

        /// <summary>
        /// Serialize a request token.
        /// </summary>
        /// <param name="model">The token to serialize</param>
        /// <returns>A byte array containing the serialized token</returns>
        public virtual byte[] Serialize(WeixinState model)
        {
            using (var memory = new MemoryStream())
            {
                using (var writer = new BinaryWriter(memory))
                {
                    Write(writer, model);
                    writer.Flush();
                    return memory.ToArray();
                }
            }
        }

        /// <summary>
        /// Deserializes a request token.
        /// </summary>
        /// <param name="data">A byte array containing the serialized token</param>
        /// <returns>The Twitter request token</returns>
        public virtual WeixinState Deserialize(byte[] data)
        {
            using (var memory = new MemoryStream(data))
            {
                using (var reader = new BinaryReader(memory))
                {
                    return Read(reader);
                }
            }
        }

        /// <summary>
        /// Writes a Twitter request token as a series of bytes. Used by the <see cref="Serialize"/> method.
        /// </summary>
        /// <param name="writer">The writer to use in writing the token</param>
        /// <param name="data">The token to write</param>
        public static void Write(BinaryWriter writer, WeixinState data)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            writer.Write(FormatVersion);
            writer.Write(data.CorrelationId);
        }

        /// <summary>
        /// Reads a Twitter request token from a series of bytes. Used by the <see cref="Deserialize"/> method.
        /// </summary>
        /// <param name="reader">The reader to use in reading the token bytes</param>
        /// <returns>The token</returns>
        public static WeixinState Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }

            string correlationId = reader.ReadString();

            return new WeixinState { CorrelationId = correlationId };
        }
    }
}
