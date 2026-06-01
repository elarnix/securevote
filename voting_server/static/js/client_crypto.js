document.addEventListener('DOMContentLoaded', () => {
    const CONFIG = {
    AUTHORITY_URL: 'https://carrier-wishlist-uncle-broadcast.trycloudflare.com ',
    // Pro Voting Server můžeme nechat prázdné nebo použít relativní cesty (je na stejném serveru jako klient)
    };
    // 1. Najdeme náš formulář pomocí jeho ID
    const voteForm = document.getElementById('voteForm');

    // 2. Přidáme "posluchače" na událost odeslání (submit)
    voteForm.addEventListener('submit', async function(event) {
        
        // 3. ZABIJEME VÝCHOZÍ CHOVÁNÍ (stránka se nesmí přenačíst!)
        event.preventDefault(); 
        
        // 1. Změna UI okamžitě po kliknutí
        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true; // Zabráníme dvojkliku
        submitBtn.textContent = "Encrypting and sending..."; // Dáme uživateli vědět, že se něco děje

        // 2. Trik: Necháme prohlížeč "vydechnout" na 50 ms, aby stihl vykreslit změny UI
        await new Promise(resolve => setTimeout(resolve, 50));
        // --- ZDE ZAČÍNÁ NAŠE LOGIKA ---
        await sodium.ready;
        
        // A. Posbíráme data z formuláře (co volič zaklikl)
        const formData = new FormData(voteForm);
        const selectedOptions = formData.getAll('vote_option'); 

        // Kontrola: Zvolil vůbec něco?
        if (selectedOptions.length === 0) {
            alert("Please, choose at least one option.");
            return;
        }

        // B. Vytáhneme si tajná data z našich skrytých inputů
        const pollId = document.getElementById('poll_id').value;
        const voterToken = document.getElementById('voter_token').value;
        
        // C. NAČTENÍ KLÍČE V HEX A PŘEVOD NA BAJTY
        const authorityPublicKeyHex = document.getElementById('authority_public_key').value;
        const authorityPublicKeyBytes = sodium.from_hex(authorityPublicKeyHex);

       // ==========================================
        // FÁZE 1: ŽÁDOST O COMMITMENT
        // ==========================================

        let R_hex;
        try {
            
            const commitmentResponse = await fetch(`${CONFIG.AUTHORITY_URL}/get_commitment`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: voterToken,
                    poll_id: pollId
                })
            });

            if (!commitmentResponse.ok) {
                const errData = await commitmentResponse.json();
                // Tady vyhodíme chybu s textem přímo ze serveru
                throw new Error(errData.error || "Unknown server error");
            }

            const commitmentData = await commitmentResponse.json();
            R_hex = commitmentData.R;

        } catch (error) {
            console.error("Error in Phase 1:", error);
            // Pokud je to naše známá chyba, ukážeme hezkou zprávu, jinak obecnou
            if (error.message.includes("Unauthorized or already voted")) {
                alert("This link has already voted (or it is invalid).");
            } else {
                alert("Error occurred when verifying link: " + error.message);
            }
            
            // Tyto řádky musí být UVNITŘ catch bloku!
            submitBtn.disabled = false;
            submitBtn.textContent = "Cast Vote";
            return; // Zastavíme vykonávání pouze při chybě
        }
        // ==========================================
        // FÁZE 2: ZASLEPENÍ A ZÍSKÁNÍ PODPISU
        // ==========================================
        let R_prime_bytes;
        let s_prime;
        try {
            // KROK 2.1: Vygenerování tajných zaslepovacích faktorů (alfa, beta)
        const alpha = sodium.crypto_core_ristretto255_scalar_random();
        const beta = sodium.crypto_core_ristretto255_scalar_random();
        
        // KROK 2.2: Odslepení Commitmentu (Výpočet R')
        const R_bytes = sodium.from_hex(R_hex);
        const alpha_G = sodium.crypto_scalarmult_ristretto255_base(alpha);
        const beta_Y = sodium.crypto_scalarmult_ristretto255(beta, authorityPublicKeyBytes);
        const alpha_G_beta_Y = sodium.crypto_core_ristretto255_add(beta_Y, alpha_G);
        R_prime_bytes = sodium.crypto_core_ristretto255_add(alpha_G_beta_Y, R_bytes);

        // KROK 2.3: Vytvoření Výzvy (Challenge c') z Hlasu a R'
        const voteString = selectedOptions.sort().join(';');
        const voteBytes = new TextEncoder().encode(voteString);
        
        const combinedBytes = new Uint8Array(R_prime_bytes.length + voteBytes.length);
        combinedBytes.set(R_prime_bytes, 0);
        combinedBytes.set(voteBytes, R_prime_bytes.length);
        
        const hash = sodium.crypto_generichash(64, combinedBytes);
        const c_prime = sodium.crypto_core_ristretto255_scalar_reduce(hash);

        // KROK 2.4: Zaslepení výzvy (c = c' + beta)
        const c = sodium.crypto_core_ristretto255_scalar_add(c_prime, beta);

        // KROK 2.5: Odeslání 'c' na Authority Server
        const c_hex = sodium.to_hex(c);
        
        const signatureResponse = await fetch(`${CONFIG.AUTHORITY_URL}/issue_signature`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: voterToken,
                    poll_id: pollId,
                    blinded_challenge: c_hex // 🛠️ OPRAVA 7: Tvoje routes.py očekává 'blinded_challenge', nikoliv 'c'.
                })
        });

        if (!signatureResponse.ok) {
            const errData = await signatureResponse.json();
            throw new Error(`Server denied the signature: ${errData.error}`);
        }
        
        const signatureData = await signatureResponse.json();
        const s_hex = signatureData.blind_signature;

        // KROK 2.6: Odslepení podpisu (s' = s + alfa)
        const s_bytes = sodium.from_hex(s_hex);
        s_prime = sodium.crypto_core_ristretto255_scalar_add(s_bytes, alpha);
        
        } catch (error) {
            console.error("Error in Phase 2:", error);
            alert("Valid signature generation was unsuccessful.");
            submitBtn.disabled = false;
            submitBtn.textContent = "Cast Vote";
            return; // Zastavíme vykonávání
        }
        
        // ==========================================
        // FÁZE 3: ODESLÁNÍ HLASU DO URNY (VOTING SERVER)
        // ==========================================

        // 3.1 Příprava finálního lístku pro Voting Server
        // Hodnoty v bajtech musíme pro přenos přes JSON převést zpět na hexadecimální stringy.
        const finalVotePayload = {
            poll_id: pollId,
            vote: selectedOptions, // odesíláme čistý hlas jako pole
            R_prime: sodium.to_hex(R_prime_bytes),
            s_prime: sodium.to_hex(s_prime)
        };

        // 3.2 Odeslání na Voting Server
        try {
            const voteResponse = await fetch('/cast_vote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(finalVotePayload)
            });

            if (!voteResponse.ok) {
                const errData = await voteResponse.json();
                throw new Error(`Voting server denied the vote: ${errData.error}`);
            }

            
            window.location.href = "/thank_you";

        } catch (error) {
            console.error("Error in Phase 3:", error);
            alert("Casting the vote was unsuccessful: " + error.message);
            submitBtn.disabled = false;
            submitBtn.textContent = "Cast Vote";
            return;
        }
    }); // Konec voteForm.addEventListener
}); // Konec document.addEventListener('DOMContentLoaded')