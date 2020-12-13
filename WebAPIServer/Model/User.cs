using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebAPIServer.Model
{
    public class User
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required, MaxLength(64)]
        public string UserName { get; set; }
        [Required, MaxLength(64)]
        public byte[] PasswordHash { get; set; }
        [Required, MaxLength(128)]
        public byte[] PasswordSalt { get; set; }
        [Required, MaxLength(20)]
        public string Phone { get; set; }
        [Required, MaxLength(20)]
        public string UserType { get; set; }
    }
}
