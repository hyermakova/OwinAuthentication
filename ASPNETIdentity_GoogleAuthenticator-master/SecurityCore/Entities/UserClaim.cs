﻿using System;
using Newtonsoft.Json;
using System.Security.Claims;

namespace SecurityCore.Entities
{
    public class UserClaim
    {
        public UserClaim(Claim claim)
        {
            if (claim == null) throw new ArgumentNullException("claim");

            Type = claim.Type;
            Value = claim.Value;
        }

        [JsonConstructor]
        public UserClaim(string type, string value)
        {
            if (type == null) throw new ArgumentNullException("claimType");
            if (value == null) throw new ArgumentNullException("claimValue");

            Type = type;
            Value = value;
        }

        public string Type { get; private set; }
        public string Value { get; private set; }
    }
}
