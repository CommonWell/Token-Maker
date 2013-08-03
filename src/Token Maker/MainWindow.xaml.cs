using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Xml;
using CommonWell.Tools.Properties;
using CommonWell.Tools.SAML;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using Formatting = Newtonsoft.Json.Formatting;

namespace CommonWell.Tools
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        public MainWindow()
        {
            InitializeComponent();
            PopulateSubjectRoles();
            PopulatePurposeOfUse();
            DateExpiration.Value = DateTime.Now.AddMinutes(5).ToUniversalTime();
            SetControlsFromSettings();
        }

        private void SetControlsFromSettings()
        {
            LabelCertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            TextBoxPassphrase.Text = Settings.Default.Passphrase;
        }

        private void PopulateSubjectRoles()
        {
            // Common roles with associated SNOMED codes
            var subjectRoles = new List<ComboBoxPairs>
                {
                    new ComboBoxPairs("Medical doctor", "112247003"),
                    new ComboBoxPairs("Hospital nurse", "394618009"),
                    new ComboBoxPairs("Pharmacist", "46255001"),
                    new ComboBoxPairs("Admnistrator", "308050009")
                };
            ComboBoxSubjectRole.ItemsSource = subjectRoles;
            ComboBoxSubjectRole.DisplayMemberPath = "Key";
            ComboBoxSubjectRole.SelectedValuePath = "Value";
            ComboBoxSubjectRole.SelectedItem = subjectRoles.First();
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
            ComboBoxPurposeOfUse.ItemsSource = purposes;
            ComboBoxPurposeOfUse.DisplayMemberPath = "Key";
            ComboBoxPurposeOfUse.SelectedValuePath = "Value";
            ComboBoxPurposeOfUse.SelectedItem = purposes.First();
        }

        private void EncodeJwt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                TextBoxJwtSignature.Clear();
                TextBoxJwtHeader.Clear();
                TextBoxJwtBody.Clear();
                if (!IsCertificateLoaded()) return;
                TextBoxJwtToken.Text = BuildJwtToken();
                DecodeJwtToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecodeJwt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!IsCertificateLoaded()) return;
                DecodeJwtToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SAML_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!IsCertificateLoaded()) return;
                TextBoxSamlToken.Text = BuildSamlToken();
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static bool IsCertificateLoaded()
        {
            bool returnValue = true;
            if (Path.IsPathRooted(Settings.Default.CertificatePath) == false)
            {
                MessageBox.Show("Select an X.509 Certificate", "X.509 Certificate Required", MessageBoxButton.OK,
                                MessageBoxImage.Exclamation);
                returnValue = false;
            }
            return returnValue;
        }

        private void DecodeJwtToken()
        {
            TextBoxJwtSignature.Clear();
            TextBoxJwtHeader.Clear();
            TextBoxJwtBody.Clear();
            ParseToken(TextBoxJwtToken.Text);
        }

        private void ParseToken(string token)
        {
            string[] parts = token.Split('.');
            JObject jsonPart = JObject.Parse(DecodeFromBase64(parts[0]));
            TextBoxJwtHeader.Text = jsonPart.ToString(Formatting.Indented);

            jsonPart = JObject.Parse(DecodeFromBase64(parts[1]));
            TextBoxJwtBody.Text = jsonPart.ToString(Formatting.Indented);

            TextBoxJwtSignature.Text = parts[2];
        }

        private string BuildJwtToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var certificate =
                new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
            var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("subjectId", TextBoxSubject.Text),
                            new Claim("subjectRole", ComboBoxSubjectRole.SelectedValue.ToString()),
                            new Claim("organization", TextBoxOrganization.Text),
                            new Claim("organizationId", TextBoxOrganizationId.Text),
                            new Claim("purposeOfUse", ComboBoxPurposeOfUse.SelectedValue.ToString()),
                            new Claim("npi", TextBoxNpi.Text)
                        }),
                    TokenIssuerName = "self",
                    TokenType = "JWT",
                    AppliesToAddress = "urn:commonwellalliance.org",
                    Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value),
                    SigningCredentials = new X509SigningCredentials(certificate)
                };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private void ChooseCertificate_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog {DefaultExt = ".pfx", Filter = "Certificates (.pfx, .p12)|*.pfx; *.p12"};
            bool? result = dlg.ShowDialog();

            if (result == true)
            {
                Settings.Default.CertificatePath = dlg.FileName;
                LabelCertificateStatus.Content = Path.GetFileName(Settings.Default.CertificatePath);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Save();
            Close();
        }

        private static string DecodeFromBase64(string encodedData)
        {
            int padding = encodedData.Length % 4;
            if (padding > 0)
            {
                encodedData += new string('=', (4 - padding));
            }
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            string returnValue = Encoding.ASCII.GetString(encodedDataAsBytes);

            return returnValue;
        }

        private void TxtPassphrase_LostFocus(object sender, RoutedEventArgs e)
        {
            SavePassphrase();
        }

        private void SavePassphrase()
        {
            if (TextBoxPassphrase.Text != Settings.Default.Passphrase)
            {
                Settings.Default.Passphrase = TextBoxPassphrase.Text;
            }
        }

        private string BuildSamlToken()
        {
            var tokenHandler = new CustomSaml2SecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                        {
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:subject-id", TextBoxSubject.Text),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:organization", TextBoxOrganization.Text),
                            new Claim("urn:oasis:names:tc:xacml:2.0:subject:role",
                                      new RoleClaim(ComboBoxSubjectRole.Text,
                                                    ComboBoxSubjectRole.SelectedValue.ToString())
                                          .ToString()),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:purposeofuse",
                                      new PurposeOfUseClaim(ComboBoxPurposeOfUse.Text,
                                                            ComboBoxPurposeOfUse.SelectedValue.ToString()).ToString()),
                            new Claim("urn:oasis:names:tc:xspa:1.0:subject:organization-id", TextBoxOrganizationId.Text)
                            ,
                            new Claim("urn:oasis:names:tc:xspa:2.0:subject:npi", TextBoxNpi.Text)
                        }),
                    TokenIssuerName = "self",
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
                    AppliesToAddress = "urn:commonwellalliance.org",
                    Lifetime = new Lifetime(DateTime.Now.ToUniversalTime(), DateExpiration.Value)
                };
            var certificate = new X509Certificate2(Settings.Default.CertificatePath, Settings.Default.Passphrase);
            tokenDescriptor.SigningCredentials = new X509SigningCredentials(certificate);
            var token = tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
            var settings = new XmlWriterSettings {Indent = true};
            var sbuilder = new StringBuilder();
            using (var writer = XmlWriter.Create(sbuilder, settings))
            {
                if (token != null) tokenHandler.WriteToken(writer, token);
            }
            return sbuilder.ToString();
        }

        private void TxtPassphrase_TextChanged(object sender, TextChangedEventArgs e)
        {
            SavePassphrase();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            Settings.Default.Save();
        }

        private void MenuItem_Click(object sender, RoutedEventArgs e)
        {
            Settings.Default.Reset();
            SetControlsFromSettings();
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
}