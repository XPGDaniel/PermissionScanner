using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Trinet.Networking;


namespace PermissionScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            string checksumfile = new FileInfo(System.Reflection.Assembly.GetEntryAssembly().Location).Directory.FullName;
            string output = checksumfile + "\\Deletable_" + DateTime.Now.ToString("yyyy-MM-dd HH-mm-ss") + ".txt";
            List<string> locations = new List<string>();// ConfigurationManager.AppSettings.AllKeys.ToList();
            List<string> excludes = ConfigurationManager.AppSettings["Exclude"].Split(';').ToList();
            excludes.RemoveAll(item => string.IsNullOrEmpty(item));
            ShareCollection shi;
            switch (Convert.ToBoolean(string.IsNullOrEmpty(ConfigurationManager.AppSettings["GetLocal"]) ? "false" : ConfigurationManager.AppSettings["GetLocal"]))
            {
                case true:
                    shi = ShareCollection.LocalShares;
                    break;
                case false:
                default:
                    if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["NAS"]))
                        shi = ShareCollection.GetShares(ConfigurationManager.AppSettings["NAS"]);
                    else
                    {
                        Console.WriteLine("Invalid setting found in app.config, program terminated.");
                        return;
                    }
                    break;
            }
            if (shi != null)
            {
                foreach (Share si in shi)
                {
                    Console.WriteLine("{0}: {1} [{2}]",
                        si.ShareType, si, si.Path);
                    if (si.ShareType == ShareType.Disk)
                        locations.Add(si.ToString().Replace(@"\\", @"\"));
                    // If this is a file-system share, try to
                    // list the first five subfolders.
                    // NB: If the share is on a removable device,
                    // you could get "Not ready" or "Access denied"
                    // exceptions.
                    //if (si.IsFileSystem)
                    //{
                    //    try
                    //    {
                    //        DirectoryInfo d = si.Root;
                    //        DirectoryInfo[] Flds = d.GetDirectories();
                    //        //for (int i = 0; i < Flds.Length && i < 5; i++)
                    //        //    Console.WriteLine("\t{0} - {1}", i, Flds[i].FullName);

                    //        //Console.WriteLine();
                    //    }
                    //    catch (Exception)
                    //    {
                    //        //Console.WriteLine("\tError listing {0}:\n\t{1}\n",
                    //        //    si, ex.Message);
                    //    }
                    //}
                }
            }
            else
                Console.WriteLine("Unable to enumerate the local shares.");


            //locations.Add(@"\\Diskstation\photo\");

            int deletable = 0;
            List<string> FileList = null;
            using (StreamWriter file = File.CreateText(output))
            { }
            foreach (var loc in locations)
            {
                Console.WriteLine("Scanning " + loc);
                FileList = GetFiles(loc, "*.*");
                if (FileList != null) if (FileList.Count != 0)
                        Console.WriteLine(FileList.Count + " files could be deleted by current user account");
                if (FileList.Any())
                {
                    using (StreamWriter file = File.AppendText(output))
                    {
                        foreach (var fi in FileList)
                        {
                            file.WriteLine(fi);
                        }
                    }
                    deletable += FileList.Count;
                }
            }
            if (FileList != null)
                Console.WriteLine("Total : " + deletable + " files could be deleted by current user account.");
            Console.WriteLine("Finished");
            Console.ReadKey();
        }
        static private List<string> GetFiles(string path, string pattern)
        {
            var files = new List<string>();

            try
            {
                if (!path.Contains("$RECYCLE.BIN") && !path.Contains("#recycle"))
                {
                    string[] candidate = Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly);
                    foreach (var s in candidate)
                    {
                        if (HasDeletePermission(s))
                            files.Add(s);
                    }
                    foreach (var directory in Directory.GetDirectories(path))
                        files.AddRange(GetFiles(directory, pattern));
                }
            }
            catch (UnauthorizedAccessException) { }

            return files;
        }
        private static bool HasDeletePermission(string FilePath)
        {
            try
            {
                FileSystemSecurity security;
                if (File.Exists(FilePath))
                {
                    security = File.GetAccessControl(FilePath);
                }
                else
                {
                    security = Directory.GetAccessControl(Path.GetDirectoryName(FilePath));
                }
                var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                var currentuser = new WindowsPrincipal(WindowsIdentity.GetCurrent());
                bool result = false;
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (0 == (rule.FileSystemRights &
                        (FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles)))
                    {
                        continue;
                    }

                    if (rule.IdentityReference.Value.StartsWith("S-1-"))
                    {
                        var sid = new SecurityIdentifier(rule.IdentityReference.Value);
                        if (!currentuser.IsInRole(sid))
                        {
                            continue;
                        }
                    }
                    else
                    {
                        if (!currentuser.IsInRole(rule.IdentityReference.Value))
                        {
                            continue;
                        }
                    }

                    if (rule.AccessControlType == AccessControlType.Deny)
                        return false;
                    if (rule.AccessControlType == AccessControlType.Allow)
                        result = true;
                }
                return result;
            }
            catch
            {
                return false;
            }
        }
    }
}
