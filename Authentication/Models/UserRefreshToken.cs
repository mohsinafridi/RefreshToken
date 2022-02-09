using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Models
{
    public class UserRefreshToken
    {
		[Key]
		public int Id { get; set; }
		[Required]
		public string UserName { get; set; }
		[Required]
		public string RefreshToken { get; set; }
		public bool IsActive { get; set; } = true;
	}
}
