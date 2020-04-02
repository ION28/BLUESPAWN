rule dev_pdb_present {
	meta:
		description = "Detects full PDB path present in target"
		license = "BSD-3"
		author = "Jake Smith"
		date = "2020-04-02"

	strings:
		$pdb_re = /.:\\Users\\.*\.pdb/ wide ascii

	condition:
		$pdb_re
}