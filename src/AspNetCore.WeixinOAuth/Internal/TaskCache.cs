using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Internal
{
    internal static class TaskCache
    {
        /// <summary>
        /// A <see cref="Task"/> that's already completed successfully.
        /// </summary>
        /// <remarks>
        /// We're caching this in a static readonly field to make it more inlinable and avoid the volatile lookup done
        /// by <c>Task.CompletedTask</c>.
        /// </remarks>
#if NET451
        public static readonly Task CompletedTask = Task.FromResult(0);
#else
        public static readonly Task CompletedTask = Task.CompletedTask;
#endif
    }
}
