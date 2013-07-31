using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Windows;

namespace CommonWell.Tools
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string _x509CertificatePath = "No Certificate";

        public MainWindow()
        {
            InitializeComponent();
            PopulateSubjectRoles();
            PopulatePurposeOfUse();
            DateExpiration.SelectedDate = DateTime.Now.AddDays(2);
            CertificateStatus.Content = _x509CertificatePath;
        }

        private void PopulateSubjectRoles()
        {
            var subjectRoles = new List<ComboBoxPairs>
                {
                    new ComboBoxPairs("Medical doctor", "112247003"),
                    new ComboBoxPairs("Hospital nurse", "394618009"),
                    new ComboBoxPairs("Pharmacist", " 46255001"),
                    new ComboBoxPairs("Admnistrator", " 308050009")
                };
            CmbSubjectRole.ItemsSource = subjectRoles;
            CmbSubjectRole.DisplayMemberPath = "Key";
            CmbSubjectRole.SelectedValuePath = "Value";
            CmbSubjectRole.SelectedItem = subjectRoles.First();
        }

        private void PopulatePurposeOfUse()
        {
            var purposes = new List<ComboBoxPairs>
                {
                    new ComboBoxPairs("Treatment", "TREATMENT"),
                    new ComboBoxPairs("Payment", "PAYMENT"),
                    new ComboBoxPairs("Healthcare Operations", "OPERATIONS"),
                    new ComboBoxPairs("Systems Administration", "SYSADMIN"),
                    new ComboBoxPairs("Fraud detection", "FRAUD"),
                    new ComboBoxPairs("Disclosure of Psychotherapy Notes", "PSYCHOTHERAPY"),
                    new ComboBoxPairs("Training", "TRAINING"),
                    new ComboBoxPairs("Legal", "LEGAL"),
                    new ComboBoxPairs("Marketing", "MARKETING"),
                    new ComboBoxPairs("Facility directories", "DIRECTORY"),
                    new ComboBoxPairs("Disclosure to family member", "FAMILY"),
                    new ComboBoxPairs("Disclosure with individual Present", "PRESENT"),
                    new ComboBoxPairs("Emergency disclosure", "EMERGENCY"),
                    new ComboBoxPairs("Disaster relief", "DISASTER"),
                    new ComboBoxPairs("Public health activities", "PUBLICHEALTH"),
                    new ComboBoxPairs("Disclosure about victim of abuse", "ABUSE"),
                    new ComboBoxPairs("Oversight activities", "OVERSIGHT"),
                    new ComboBoxPairs("Judicial proceedings", "JUDICIAL"),
                    new ComboBoxPairs("Law enforcement", "LAW"),
                    new ComboBoxPairs("Disclosure about decedent", "DECEASED"),
                    new ComboBoxPairs("Organ donation", "DONATION"),
                    new ComboBoxPairs("Dsclosure for research", "RESEARCH"),
                    new ComboBoxPairs("Disclosure to avert threat", "THREAT"),
                    new ComboBoxPairs("Specialized government function", "GOVERNMENT"),
                    new ComboBoxPairs("Worker's compensation", "WORKERSCOMP"),
                    new ComboBoxPairs("Insurance/Disability coverage", "COVERAGE"),
                    new ComboBoxPairs("Request of the individual", "REQUEST")
                };
            CmbPurposeOfUse.ItemsSource = purposes;
            CmbPurposeOfUse.DisplayMemberPath = "Key";
            CmbPurposeOfUse.SelectedValuePath = "Value";
            CmbPurposeOfUse.SelectedItem = purposes.First();
        }

        private void Encode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
            TxtTokenString.Text = BuildToken();
            }
            catch (Exception err)
            {
                TxtTokenString.Text = err.Message;
            }
        }

        private string BuildToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var certificate =
                new X509Certificate2(_x509CertificatePath, TxtPassphrase.Text);

            DateTime now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("Subject ID", TxtSubject.Text),
                            new Claim("Subject Organization", TxtOrganization.Text),
                            new Claim("Subject Role", CmbSubjectRole.SelectedValue.ToString(), "CE", "SNOMED_CT"),
                            new Claim("Purpose of Use", CmbPurposeOfUse.SelectedValue.ToString(), "nhin-purpose"),
                            new Claim("Organization ID", TxtOrganizationId.Text),
                            new Claim("National Provider Identifier", "1245319598"),
                        }),
                    TokenIssuerName = "self",
                    TokenType = "JWT",
                    AppliesToAddress = "urn:commonwellalliance.org",
                    Lifetime = new Lifetime(now, DateExpiration.SelectedDate),
                    SigningCredentials = new X509SigningCredentials(certificate)
                };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private void ChooseCertificate_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog {DefaultExt = ".pfx", Filter = "Certificates (.pfx, .p12)|*.pfx; *.p12"};
            bool? result = dlg.ShowDialog();

            if (result == true)
            {
                string filename = dlg.FileName;
                _x509CertificatePath = filename;
                CertificateStatus.Content = System.IO.Path.GetFileName(_x509CertificatePath);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    internal class ComboBoxPairs
    {
        public ComboBoxPairs(string key, string value)
        {
            Key = key;
            Value = value;
        }

        public string Key { get; set; }
        public string Value { get; set; }
    }
}