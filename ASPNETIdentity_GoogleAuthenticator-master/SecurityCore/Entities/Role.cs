﻿using System;
using Microsoft.AspNet.Identity;

namespace SecurityCore.Entities
{
    public class Role: IRole<int>
    {
        public Role()
        {

        }

        public Role(string name)
        {
            this.Name = name;
        }

        public Role(int id, string name)
        {
            this.Id = Id;
            this.Name = name;
        }
        
        public int Id { get; set; }
        public string Name { get; set; }
    }
}
