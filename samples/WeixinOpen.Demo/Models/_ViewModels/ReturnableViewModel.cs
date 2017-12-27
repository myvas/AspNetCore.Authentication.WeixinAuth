using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WeixinOpen.Demo.Models
{
    public class ReturnableViewModel
    {
        [Display(Name = "Return to entrance")]
        public string ReturnUrl { get; set; }
    }

    public class ReturnableViewModel<T>
        : ReturnableViewModel
    {
        public T Data { get; set; }
    }
}
