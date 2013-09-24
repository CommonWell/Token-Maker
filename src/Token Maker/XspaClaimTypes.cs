namespace CommonWell.Tools
{
    /// <summary>
    /// Claims used in the xspa specification.
    /// </summary>
    public static class XspaClaimTypes
    {
        /// <summary>
        /// SubjectIdentifier.
        /// </summary>
        public const string SubjectIdentifier = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

        /// <summary>
        /// SubjectOrganization.
        /// </summary>
        public const string SubjectOrganization = "urn:oasis:names:tc:xpsa:1.0:subject:organization";

        /// <summary>
        /// SubjectRole.
        /// </summary>
        public const string SubjectRole = "urn:oasis:names:tc:xacml:2.0:subject:role";

        /// <summary>
        /// PurposeOfUse.
        /// </summary>
        public const string PurposeOfUse = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";

        /// <summary>
        /// OrganizationIdentifier.
        /// </summary>
        public const string OrganizationIdentifier = "urn:oasis:names:tc:xspa:1.0:subject:organization-id";

        /// <summary>
        /// NationalProviderIdentifier.
        /// </summary>
        public const string NationalProviderIdentifier = "urn:oasis:names:tc:xspa:2.0:subject:npi";

        /// <summary>
        /// The address that a claim applies to.
        /// </summary>
        public const string AppliesToAddress = "urn:commonwellalliance.org";
    }

    /// <summary>
    /// Claims used in the xspa specification.
    /// </summary>
    public static class IUAClaimTypes
    {

        /// <summary>
        /// The jti (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object. The jti claim can be used to prevent the JWT from being replayed. The jti value is a case sensitive string. Use of this claim is REQUIRED per the IHE Internet User Authorization (IUA) profile.
        /// </summary>
        public const string JWT_ID = "jti";

        /// <summary>
        /// The sub (subject) claim identifies the principal that is the subject of the JWT. The Claims in a JWT are normally statements about the subject. The processing of this claim is generally application specific. The sub value is a case sensitive string containing a StringOrURI value. Use of this claim is REQUIRED per the IHE Internet User Authorization (IUA) profile.
        /// </summary>
        public const string Subject = "sub";

        /// <summary>
        /// Plain text user's name.
        /// </summary>
        public const string SubjectIdentifier = "SubjectID";

        /// <summary>
        /// Plain text description of the organization.
        /// </summary>
        public const string SubjectOrganization = "SubjectOrganization";

        /// <summary>
        /// SNOMED Code identifying subject role.
        /// </summary>
        public const string SubjectRole = "SubjectRole";

        /// <summary>
        /// Purpose of use for the request.
        /// </summary>
        public const string PurposeOfUse = "PurposeOfUse";

        /// <summary>
        /// OrganizationIdentifier.
        /// </summary>
        public const string OrganizationIdentifier = "SubjectOrganizationID";

        /// <summary>
        /// Home Community ID where request originated.
        /// </summary>
        public const string HomeCommunictyID = "HomeCommunityID";

        /// <summary>
        /// Phsyician's NPI.
        /// </summary>
        public const string NationalProviderIdentifier = "NationalProviderIdentifier";

        /// <summary>
        /// The address that a claim applies to.
        /// </summary>
        public const string AppliesToAddress = "urn:commonwellalliance.org";
    }
}
