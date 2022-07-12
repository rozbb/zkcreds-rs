struct IssuerState {
    /// The forest of commitments
    com_forest: ComForest,
    /// The next free tree to insert a commitment
    next_free_tree: usize,
    /// The next free leaf in that tree to insert a commitment
    next_free_leaf: u64,
}

struct UserState {
    /// The original passport dump
    dump: PassportDump,
    /// The private attributes the user retains
    attrs: PersonalInfo,
    /// The auth path of my cred in one of the commitment trees
    auth_path: Option<ComTreePath>,
    /// The roots of the forest that this credential appears in
    roots: Option<ComTreeRoots>,
}

// Generates all the CRSs
fn gen_crs<R: Rng>(rng: &mut R) -> CrsTable {
    let mut rng = rand::thread_rng();
    let mut table = CrsTable::new();

    // Generate all the mandatory CRSs first: issuance and tree/forest memberhsip
    table.insert("issuance", PassportHashChecker::default().gen_crs(&rng));
    table.insert("tree", gen_tree_member_crs(&mut rng, TREE_HEIGHT));
    table.insert("forest", gen_forest_member_crs(&mut rng, NUM_TREES));

    // Now generate the CRSs for the predicates
    table.insert("age", AgeChecker::new(TWENTY_ONE_YEARS_AGO).gen_crs(&rng));
    table.insert("face", FaceChecker::default().gen_crs(&rng));
    table.insert("expiry", ExpiryChecker::new(TODAY).gen_crs(&rng));
    table.insert("multishow", MultishowChecker::default().gen_crs(&rng));

    table
}

fn main() {
    // Global setup happens once
    let rng = rand::thread_rng();
    let crs_table = gen_crs(&mut rng);

    // A user scans his passport and parses it into Attributes
    let dump = load_passport_dump("user_passport.json");
    let mut user_state = UserState::from_dump(dump);

    // Next step is for the user to ask for issuance
    let isu_req = user_state.issue_req(&mut rng, &crs_table);

    //
    // User   --- isu_req --->   Issuer
    //

    // Start the issuer
    let mut issuer_state = load_issuer_state("issuer_state.json");
    // Check the issuance request
    match issuer_state.issue(&isu_req, &crs_table) {
        Some(auth_path) => {
            // Issuance check succeeded. Return the auth path
            send_to_user(auth_path);
        }
        None => {
            // Issuance check failed. Do nothing
        }
    }

    //
    // User   <--- auth_path, forest_roots ---   Issuer
    //

    // The user computes their membership proofs and saves them for later
    user.set_auth_path(auth_path);
    user.set_roots(forest_roots);
    let memb_proof = user_state.prove_memb(&mut rng, &crs_table);

    //
    // A user walks into a bar
    //

    // The user has a bunch of things to prove now. They need to prove their age, their face, and
    // their passport expiry.
    let (age_proof, age_pub_inputs) = user_state.prove_pred(
        rng,
        AgeChecker::new(TWENTY_ONE_YEARS_AGO),
        "age",
        &crs_table,
    );
    let (expiry_proof, expiry_pub_inputs) =
        user_state.prove_pred(&mut rng, ExpiryChecker::new(TODAY), "expiry", &crs_table);

    // To give a face proof, the user also has to provide public inputs, namely the hash of their
    // image.
    let face = user_state.get_face();
    let (face_proof, face_pub_inputs) =
        user_state.prove_pred(&mut rng, FaceChecker::new(face.hash()), "face", &crs_table);

    // Finally the user links all the proofs together
    let cred = user_state.cred();
    let my_root = user_state.tree_root();
    let link_prover = LinkProver::new()
        .with_crs(&crs_table)
        .with_cred(cred)
        .in_forest(memb_proof, (&forest_roots, &my_root))
        .add_pred("age", age_proof, age_pub_inputs)
        .add_pred("expiry", expiry_proof, expiry_pub_inputs)
        .add_pred("face", face_proof, face_pub_inputs);
    let link_proof = link_prover.prove(&mut rng);

    //
    // User  --- link_proof, face ---> Bar
    //

    // The verifier has to make their own public inputs from the predicates, since they might
    // differ from the public inputs used by the prover.
    let age_pub_inputs = AgeChecker::new(TWENTY_ONE_YEARS_AGO).public_inputs();
    let expiry_pub_inputs = ExpiryChecker::new(TODAY).public_inputs();
    let face_pub_inputs = FaceChecker::new(face.hash()).public_inputs();

    // Make the linkage verifier. Notice that the order of the predicates is different. They're
    // sorted under the hood
    let link_verifier = LinkVerifier::new()
        .with_crs(&crs_table)
        .in_forest(&forest_roots)
        .add_pred("expiry", expiry_pub_inputs)
        .add_pred("face", face_pub_inputs)
        .add_pred("age", age_pub_inputs);
    assert!(link_verifier.verify(&link_proof));

    // Finally, show the verified face to the bouncer
    show_image(face);
}

//
// Define some helper methods for main() above
//

impl UserState {
    /// Initializes a UserState from a passport dump
    fn from_dump(dump: PassportDump) -> UserState {
        // Turn the passport dump into attributes
        let attrs = PersonalInfo::from_passport(rng, &dump, TODAY, MAX_VALID_YEARS);

        UserState {
            dump,
            attrs,
            auth_path: None,
            roots: None,
        }
    }

    /// Constructs an issuance request
    fn issue_req<R: Rng>(&self, rng: &mut R, crs_table: &CrsTable) -> IssueReq {
        // Get the proving key for issuance
        let issuance_pk = crs_table.get("issuance", CrsType::ProvingKey).unwrap();

        // Make a hash checker using our private data, and prove the predicate
        let hash_checker =
            PassportHashChecker::from_passport(&self.dump, ISSUING_STATE, TODAY, MAX_VALID_YEARS);
        let hash_proof = hash_checker
            .prove_birth(rng, issuance_pk, &self.attrs)
            .unwrap();

        // Our credential is the commitment to our attributes
        let cred = self.attrs.com();

        // Now put together the issuance request
        let req = IssuanceReq {
            cred,
            econtent_hash: self.dump.econtent_hash(),
            sig: self.dump.sig,
            hash_proof,
        };
    }

    // Returns this user's face
    fn get_face(&self) -> &Biometrics {
        &self.attrs.face
    }

    // Returns this user's credential
    fn cred(&self) -> Com {
        self.attrs.com()
    }

    // Returns the root of the tree that our cred resides in
    fn tree_root(&self) -> ComTreeRoot {
        self.auth_path.root()
    }

    /// Proves anything at all about this user. Returns the proof and any public inputs that the
    /// verifier will need
    fn prove_pred<R, P>(
        &self,
        rng: &mut R,
        pred: &P,
        pred_name: &str,
        crs_table: &CrsTable,
    ) -> (PredProof, PredPublicInput)
    where
        R: Rng,
        P: PredicateChecker<PersonalInfo, PersonalInfoVar>,
    {
        // Get the proving key for this predicate
        let pred_pk = crs_table.get(pred_name, CrsType::ProvingKey).unrwap();
        // Prove the statement
        let proof = pred.prove_pred(rng, pred_pk, self.attrs, self.auth_path.unwrap());
        // Collect the public inputs
        let pub_input = pred.public_inputs();

        (proof, pub_input)
    }

    // Proves membership of this cred in the Merkle forest
    fn prove_memb<R: Rng>(&self, rng: &mut R, crs_table: &CrsTable) -> MembershipProof {
        let cred = self.attrs.com();
        prove_merkle_membership(rng, crs_table, cred, &self.auth_path, self.roots)
    }
}

impl IssuerState {
    /// Checks an issuance request and, on success adds it to the tree
    fn issue(&mut self, req: &IssuanceReq, crs_table: &CrsTable) -> Option<ComTreePath> {
        // Get the verifying key for issuance
        let issuance_vk = crs_table.get("issuance", CrsType::VerifyingKey).unwrap();

        // Construct the verifier context from the issuance request
        let hash_checker =
            PassportHashChecker::from_issuance_req(req, ISSUING_STATE, TODAY, MAX_VALID_YEARS);
        let sig_pubkey = load_usa_pubkey();
        let cred = &req.cred;

        // Check the issuance proof
        if hash_checker.verify_birth(&issuance_vk, &req.hash_proof, cred) {
            // On success, insert the commitment into the tree
            let auth_path =
                state.com_forest.trees[state.next_free_tree].insert(state.next_free_leaf, &cred);
            // Increment next empty slot
            state.next_free_leaf += 1;
            // Return the auth path
            Some(auth_path)
        } else {
            // Verification failed. Do nothing
            None
        }
    }
}
