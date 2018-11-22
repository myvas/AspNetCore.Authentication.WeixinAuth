using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Myvas.AspNetCore.Authentication.QQConnect
{
    public class PhotoUploadPictureRequestParameters
    {
        public AlbumCategory Category { get; set; }
        /// <summary>
        /// 相册ID
        /// </summary>
        public string AlbumId { get; set; }

        public Photo[] Photos { get; set; }

    }

    public class AlbumCategory
    {
        public const string Phone = "Phone";
        public const string Qzone = "Qzone";
    }

    public class Photo
    {
        /// <summary>
        /// 照片名称，不能超过30个字符
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// 照片描述
        /// </summary>
        public string Description { get; set; }
        /// <summary>
        /// 照片数据
        /// </summary>
        public Stream Pictures { get; set; }
        /// <summary>
        /// 拍摄地理位置
        /// </summary>
        public GpsLocation Location { get; set; }
    }

    public class GpsLocation
    {
        /// <summary>
        /// 纬度
        /// </summary>
        public decimal Latitude { get; set; }

        /// <summary>
        /// 经度
        /// </summary>
        public decimal Longitude { get; set; }
    }
}
