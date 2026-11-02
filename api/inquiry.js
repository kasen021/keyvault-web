export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { service, name, contact, description } = req.body;
  const prices = { 'gen-cryptos':'Rp250.000','blockchain':'Rp800.000','cryptanalysis':'Rp10.000.000','nos-vpn-cyborg':'Rp20.000','nos-vpn-cypherstar':'Rp50.000' };
  if (!prices[service]) return res.status(400).json({ error: 'Layanan tidak valid.' });
  if (!name || !contact || !description) return res.status(400).json({ error: 'Lengkapi semua field.' });
  const btc = { 'nos-vpn-cyborg': process.env.BTC_CYBORG, 'nos-vpn-cypherstar': process.env.BTC_CYPHERSTAR };
  return res.status(200).json({ status:'received', service, price: prices[service], btc_address: btc[service] || process.env.BTC_MAIN, note:'Harga BTC auto-convert dari IDR via CoinGecko.' });
}
