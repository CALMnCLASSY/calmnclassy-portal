const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

// Use the PORT provided by Render or default to 3000
const PORT = process.env.PORT || 3000;

// Paystack sends the body as a JSON object
app.use(express.json());

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/paystack-webhook', (req, res) => {
    // 1. Retrieve the signature from headers
    const signature = req.headers['x-paystack-signature'];
    const secret = process.env.PAYSTACK_SECRET_KEY;

    if (!signature) {
        console.error("Missing Paystack Signature Header");
        return res.status(401).send('No signature provided');
    }

    // 2. Compute the HMAC SHA512 hash using your Secret Key
    const hash = crypto
        .createHmac('sha512', secret)
        .update(JSON.stringify(req.body))
        .digest('hex');

    // 3. Timing-safe comparison to prevent side-channel attacks
    // This is the "Gold Standard" for security
    const isVerified = crypto.timingSafeEqual(
        Buffer.from(hash),
        Buffer.from(signature)
    );

    if (!isVerified) {
        console.error("❌ UNAUTHORIZED: Invalid Signature Detected");
        return res.status(401).send('Invalid Signature');
    }

    // 4. Handle the verified event
    const event = req.body;
    console.log(`✅ VERIFIED: Processing ${event.event}...`);

    switch (event.event) {
        case 'charge.success':
            const customerEmail = event.data.customer.email;
            const amount = event.data.amount / 100; // Convert from kobo/cents to main unit
            console.log(`💰 Payment of ${amount} confirmed for ${customerEmail}`);
            // ADD YOUR DATABASE LOGIC HERE (e.g., Update Supabase status)
            break;

        case 'transfer.success':
            console.log("💸 Payout to your bank was successful");
            break;

        default:
            console.log(`Unhandled Event Type: ${event.event}`);
    }

    // Paystack requires a 200 OK to stop retrying the webhook
    res.status(200).send('Webhook Processed');
});

app.get('/', (req, res) => res.send('CALMnCLASSY Secure API Gateway Active.'));

// Serve index.html for all other routes (SPA routing)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 Secure Agency API live on port ${PORT}`));