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
}
