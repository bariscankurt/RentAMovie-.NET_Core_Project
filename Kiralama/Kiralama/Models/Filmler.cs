using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Kiralama.Models
{
    public class Filmler
    {
        public int Id { get; set; }
        public string FilmAdi { get; set; }
        public string ResimYolu { get; set; }
        public string Tur { get; set; }
        public string Dil { get; set; }
        public string Sure { get; set; }
        public string Aciklama { get; set; }
        public string Yonetmen { get; set; }
        public string Oyuncular { get; set; }
        public int KiralamaUcreti { get; set; }

        [NotMapped]
        public bool IsPurchased { get; set; }
    }
}
