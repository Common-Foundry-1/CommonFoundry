"""HiveOS interface checks; no mining or network connection is started."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import package_mainnet as package
import mainnet_release as release


class HivePackageIdentityTests(unittest.TestCase):
    def test_release_inventory_contains_all_five_archives_and_evidence(self):
        names=(ROOT/'packaging/releases/v1.0.0.inventory').read_text().splitlines()
        expected=release.BASE_EVIDENCE | set(release.archive_names('1.0.0').values()) | {
            release.REPRODUCTION, release.REPRODUCTION_SIGNATURE}
        self.assertEqual(names,sorted(expected))

    def test_custom_get_filename_and_top_level_match_manifest_paths(self):
        root,archive=package.package_names('linux-x86_64','hiveos','1.0.0')
        self.assertEqual(root,'commonfoundry-mainnet-hiveos')
        self.assertEqual(archive,root+'-1.0.0.tar.gz')
        self.assertEqual(archive.removesuffix('.tar.gz').rsplit('-',1)[0],root)
        manifest=(ROOT/'packaging/mainnet/hiveos/h-manifest.conf').read_text()
        self.assertIn('CUSTOM_NAME='+root+'\n',manifest)
        self.assertIn('CUSTOM_CONFIG_FILENAME=/hive/miners/custom/'+root+'/miner.json',manifest)
        self.assertNotIn('/hive/custom/',manifest)
        self.assertIn(('linux-x86_64','hiveos'),package.PACKAGE_ROLES)

    def test_ambiguous_hive_version_and_windows_role_are_rejected(self):
        with self.assertRaises(package.Error):package.package_names('linux-x86_64','hiveos','1.0.0-mainnet.1')
        with self.assertRaises(package.Error):package.package_names('windows-x86_64','hiveos','1.0.0')


@unittest.skipUnless(sys.platform.startswith('linux'),'HiveOS callbacks require Linux')
class HiveAdapterTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('cmfd_hive_fixture',ROOT/'packaging/mainnet/hiveos/hive-adapter.py')
        self.adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.adapter)
        temporary=tempfile.TemporaryDirectory(prefix='cmfd-hive-interface-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.install=self.root/'custom/commonfoundry-mainnet-hiveos';self.install.mkdir(parents=True)
        self.args=type('Arguments',(),{'root':self.install,'config':self.install/'miner.json','log_base':self.root/'logs/miner'})()
        self.config={'wallet':'11'*32,'pool':'cmfd+tls://203.0.113.7:29445?pin='+'aa'*32,
                     'worker':'fixture','gpus':[0,2],'model_dir':str(self.root/'persistent/models'),'state_dir':str(self.root/'persistent/state')}

    def test_invalid_flight_sheet_marks_old_config_unusable(self):
        self.adapter.atomic_json(self.args.config,self.config)
        with mock.patch.dict(os.environ,{'CMFD_HIVE_TEMPLATE':'11'*32,'CMFD_HIVE_URL':self.config['pool'],
                'CMFD_HIVE_WORKER':'fixture','CMFD_HIVE_OPTIONS':'{"worker":"$(touch unwanted)"}'}):
            with self.assertRaises(ValueError):self.adapter.configure(self.args)
        self.assertTrue(self.args.config.with_suffix('.json.invalid').exists())
        with self.assertRaisesRegex(ValueError,'latest flight-sheet'):self.adapter.run(self.args)

    def test_model_directory_inside_reinstalled_folder_is_rejected(self):
        self.config['model_dir']=str(self.install/'models')
        with self.assertRaisesRegex(ValueError,'outside'):self.adapter.validate_config(self.config,self.install)

    def test_unpinned_pool_and_ambiguous_gpu_selection_are_rejected(self):
        for pool in ['http://203.0.113.7:80','cmfd+tls://example.com:123?pin='+'aa'*32,
                     'cmfd+tls://203.0.113.7:123?pin='+'aa'*32+'&pin='+'bb'*32]:
            with self.subTest(pool=pool),self.assertRaises(ValueError):self.adapter.validate_config(dict(self.config,pool=pool),self.install)
        for gpus in [[1,1],[-1],['0'],[True]]:
            with self.subTest(gpus=gpus),self.assertRaises(ValueError):self.adapter.validate_config(dict(self.config,gpus=gpus),self.install)

    def test_stats_use_bus_ids_and_reject_stale_logs_or_reused_pids(self):
        gpu={'uuid':'GPU-00000000-0000-0000-0000-000000000001','index':3,'bus':17,'temp':62,'fan':71}
        self.args.log_base.parent.mkdir()
        logfile=self.args.log_base.parent/('gpu-'+gpu['uuid']+'.log')
        logfile.write_text('MINER STATS | GPU 3 ('+gpu['uuid']+') | height 5 | hashrate 23.50 FW/s | accepted 17 | rejected 2 | stale 1 | blocks 2 | credit 100 atoms | power 150 W | efficiency 22 FW/kWh | temp 62 C | uptime 01:02:03\n')
        (self.install/'h-manifest.conf').write_text('CUSTOM_VERSION=1.0.0\n')
        state={'running':True,'manager_pid':1,'manager_start':'old','workers':[{'pid':2,'start':'old','gpu':gpu,'log':str(logfile)}]}
        self.adapter.atomic_json(self.args.log_base.parent/'state.json',state)
        with mock.patch.object(self.adapter,'process_identity',return_value='old'),mock.patch.object(self.adapter,'gpu_inventory',return_value=[gpu]):
            result=self.adapter.stats(self.args)
            self.assertEqual(result['khs'],0.0235);self.assertEqual(result['stats']['bus_numbers'],[17])
            self.assertEqual(result['stats']['ar'],[17,2]);self.assertEqual(result['stats']['uptime'],3723)
            os.utime(logfile,(time.time()-60,time.time()-60))
            self.assertIsNone(self.adapter.stats(self.args)['stats'])
        with mock.patch.object(self.adapter,'process_identity',return_value='replacement'):
            self.assertIsNone(self.adapter.stats(self.args)['stats'])


if __name__=='__main__':unittest.main()
