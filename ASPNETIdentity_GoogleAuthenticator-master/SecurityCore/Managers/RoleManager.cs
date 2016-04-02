using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using SecurityCore.Entities;
using SecurityCore.Repositories;
using System;

namespace SecurityCore.Managers
{
    public class RoleManager : RoleManager<Role, int>
    {
        static string folderStorage = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "_Storage");

        public RoleManager(IRoleStore<Role, int> roleStore)
            : base(roleStore)
        {
        }

        public static RoleManager Create(IdentityFactoryOptions<RoleManager> options, IOwinContext context)
        {
            var manager = new RoleManager(new RoleRepository(folderStorage));

            return manager;
        }
    }

}
