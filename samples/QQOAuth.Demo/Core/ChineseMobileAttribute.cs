using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace System.ComponentModel.DataAnnotations
{
    /// <summary>
    /// <see cref="PhoneAttribute"/>
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter, AllowMultiple = false)]

    public sealed class ChineseMobileAttribute : DataTypeAttribute
    {
        private static Regex _regex = CreateRegex();
        private const string _additionalPhoneNumberCharacters = "-.()";
        private const string DefaultErrorMessage = "The {0} field is not a valid phone number.";

        public static bool DisableRegex { get; set; }
        public static TimeSpan REGEX_DEFAULT_MATCH_TIMEOUT { get; set; } = TimeSpan.FromSeconds(2);

        public ChineseMobileAttribute()
            : base(DataType.PhoneNumber)
        {
        }
        public ChineseMobileAttribute(DataType dataType)
            : base(dataType)
        {
        }

        public static bool Validate(object value)
        {
            if (value == null) return false;

            string valueAsString = value as string;

            return valueAsString != null
                       && _regex.Match(valueAsString).Length > 0;
        }

        public override bool IsValid(object value)
        {
            if (value == null)
            {
                return true;
            }

            string valueAsString = value as string;

            if (_regex != null)
            {
                return valueAsString != null
                    && _regex.Match(valueAsString).Length > 0;
            }
            else
            {
                if (valueAsString == null)
                {
                    return false;
                }

                valueAsString = valueAsString.Replace("+", "").TrimEnd();

                bool digitFound = false;
                foreach (char c in valueAsString)
                {
                    if (Char.IsDigit(c))
                    {
                        digitFound = true;
                        break;
                    }
                }

                if (!digitFound)
                {
                    return false;
                }

                foreach (char c in valueAsString)
                {
                    if (!(Char.IsDigit(c)
                        || Char.IsWhiteSpace(c)
                        || _additionalPhoneNumberCharacters.IndexOf(c) != -1))
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        private static Regex CreateRegex()
        {
            if (DisableRegex)
            {
                return null;
            }

            const string pattern = @"^1[3|5|7|8|9]\d{9}$";
            const RegexOptions options = RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture;

            TimeSpan matchTimeout = REGEX_DEFAULT_MATCH_TIMEOUT;

            try
            {
                return new Regex(pattern, options, matchTimeout);
            }
            catch
            {
                // Fallback on error
            }

            // Legacy fallback (without explicit match timeout)
            return new Regex(pattern, options);


        }
    }
}
