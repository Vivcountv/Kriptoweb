import React, { useState } from 'react';
import { 
    Upload, Send, Mail, KeyRound, Copy, CheckCircle, AlertTriangle, 
    Loader2, Lock, Unlock, Eye, EyeOff, Shield, Download, // <-- Pastikan 'Download' sudah diimpor
    ImageIcon, FileText, Zap, Sparkles, ChevronDown, ChevronUp, X
} from 'lucide-react';

// === Komponen UI (Alert, FeatureCard, TabButton, dll.) tidak berubah ===
// (Kode komponen ini sama seperti sebelumnya)
const Alert = ({ message, type, onDismiss }) => {
    if (!message) return null;
    const styles = {
        error: { bg: 'bg-red-100', border: 'border-red-500', text: 'text-red-700', icon: AlertTriangle },
        success: { bg: 'bg-green-100', border: 'border-green-500', text: 'text-green-700', icon: CheckCircle }
    }[type] || { bg: 'bg-blue-100', border: 'border-blue-500', text: 'text-blue-700', icon: Info };
    const Icon = styles.icon;
    return (
        <div className={`mt-4 p-4 rounded-xl border-l-4 ${styles.bg} ${styles.border} ${styles.text} flex items-start justify-between shadow-sm`}>
            <div className="flex items-start gap-3"><Icon className="h-5 w-5 mt-0.5 flex-shrink-0" /><span className="text-sm font-medium">{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="text-current hover:opacity-70 transition-opacity"><X className="h-4 w-4" /></button>}
        </div>
    );
};
const FeatureCard = ({ icon: Icon, title, description, color }) => {
    const colorClasses = {
        blue: "bg-blue-50 text-blue-700 border-blue-200",
        green: "bg-green-50 text-green-700 border-green-200",
        purple: "bg-purple-50 text-purple-700 border-purple-200",
        amber: "bg-amber-50 text-amber-700 border-amber-200"
    };
    return (
        <div className={`p-4 rounded-xl border ${colorClasses[color]} transition-all duration-200 hover:shadow-md`}>
            <div className="flex items-start gap-3">
                <div className="p-2 bg-white rounded-lg shadow-sm"><Icon className="h-5 w-5" /></div>
                <div><h3 className="font-semibold text-sm">{title}</h3><p className="text-xs opacity-80 mt-1">{description}</p></div>
            </div>
        </div>
    );
};
const TabButton = ({ id, activeTab, setActiveTab, icon, label, color }) => {
    const isActive = activeTab === id;
    const colorClasses = {
        blue: isActive ? 'border-blue-500 text-blue-600 bg-blue-50' : 'hover:text-blue-600 hover:border-blue-300',
        purple: isActive ? 'border-purple-500 text-purple-600 bg-purple-50' : 'hover:text-purple-600 hover:border-purple-300'
    };
    return (
        <button onClick={() => setActiveTab(id)} className={`flex items-center gap-2 font-medium text-lg px-6 py-3 rounded-t-xl border-b-2 transition-all duration-200 ${isActive ? `${colorClasses[color]} shadow-sm` : `border-transparent text-slate-500 ${colorClasses[color]}`}`}>{icon}{label}</button>
    );
};

// === Panel Pengirim (SenderPanel) tidak berubah ===
const SenderPanel = ({ onNewKeyGenerated }) => {
    const [message, setMessage] = useState('');
    const [coverImage, setCoverImage] = useState(null);
    const [coverPreview, setCoverPreview] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [outputKey, setOutputKey] = useState(null);
    const [error, setError] = useState('');
    const [showKey, setShowKey] = useState(false);

    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setCoverImage(file);
            setCoverPreview(URL.createObjectURL(file));
            setOutputKey(null);
        }
    };
    
    const handleCopyKey = () => {
        if (!outputKey) return;
        navigator.clipboard.writeText(outputKey)
            .then(() => {
                alert('Kunci Universal berhasil disalin!');
                // Otomatis pindah tab dan paste kunci
                if (onNewKeyGenerated) {
                    onNewKeyGenerated(outputKey);
                }
            })
            .catch(err => console.error('Gagal menyalin kunci:', err));
    };

    const handleEncrypt = async () => {
        if (!message || !coverImage) {
            setError('Pesan dan gambar sampul tidak boleh kosong!');
            return;
        }
        setIsLoading(true);
        setError('');
        setOutputKey(null);

        const formData = new FormData();
        formData.append('message', message);
        formData.append('image', coverImage);

        try {
            const response = await fetch('http://127.0.0.1:5000/api/encrypt', {
                method: 'POST',
                body: formData,
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Terjadi kesalahan di server.');
            
            setOutputKey(result.receiverKey);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="space-y-6">
            {error && <Alert message={error} type="error" onDismiss={() => setError('')} />}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><FileText className="h-5 w-5 text-blue-600" /><label htmlFor="message" className="text-sm font-semibold text-slate-700">Pesan Rahasia (max 16 char)</label></div>
                    <textarea id="message" maxLength={16} rows="6" value={message} onChange={(e) => setMessage(e.target.value)} className="w-full p-4 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500" placeholder="Masukkan pesan..."/>
                </div>
                <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><ImageIcon className="h-5 w-5 text-green-600" /><label className="text-sm font-semibold text-slate-700">Gambar Sampul</label></div>
                    <div className="border-2 border-dashed border-slate-300 rounded-xl p-6 text-center hover:border-blue-400">
                        <input type="file" id="cover-image" accept="image/png, image/jpeg" onChange={handleImageChange} className="hidden"/>
                        <label htmlFor="cover-image" className="cursor-pointer">
                            {coverPreview ? <img src={coverPreview} className="rounded-lg max-h-48 mx-auto border shadow-sm" alt="Preview"/> : <div className="space-y-2"><Upload className="h-12 w-12 text-slate-400 mx-auto" /><p>Pilih gambar</p></div>}
                        </label>
                    </div>
                </div>
            </div>
            <button onClick={handleEncrypt} disabled={isLoading || !message || !coverImage} className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold py-4 px-6 rounded-xl flex items-center justify-center gap-3 shadow-lg disabled:opacity-50">
                {isLoading ? <><Loader2 className="animate-spin h-5 w-5" />Memproses...</> : <><Lock className="h-5 w-5" />Buat Kunci Universal</>}
            </button>
            {outputKey && (
                <div className="mt-8 space-y-4 pt-6 border-t">
                    <Alert message="Berhasil! Salin Kunci Universal untuk diberikan ke penerima atau langsung pindah tab." type="success"/>
                    <div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2"><KeyRound className="h-5 w-5 text-purple-600" /><h4 className="font-semibold text-lg">Kunci Universal</h4></div>
                            <button onClick={() => setShowKey(!showKey)} className="text-sm flex items-center gap-1">{showKey ? <EyeOff size={14}/> : <Eye size={14}/>}{showKey ? 'Sembunyikan' : 'Tampilkan'}</button>
                        </div>
                        <textarea readOnly rows="8" value={outputKey} className={`w-full p-4 mt-2 bg-slate-50 border rounded-xl font-mono text-xs ${!showKey && 'blur-sm'}`}/>
                        <button onClick={handleCopyKey} className="w-full mt-2 bg-purple-100 text-purple-700 px-4 py-2 rounded-lg flex items-center justify-center gap-2 hover:bg-purple-200 transition-colors"><Copy className="h-4 w-4" />Salin & Pindah ke Penerima</button>
                    </div>
                </div>
            )}
        </div>
    );
};

// === PERUBAHAN DI ReceiverPanel ===
const ReceiverPanel = ({ universalKey, setUniversalKey }) => {
    const [isLoading, setIsLoading] = useState(false);
    const [output, setOutput] = useState(null);
    const [error, setError] = useState('');

    const handleDecrypt = async () => {
        if (!universalKey) {
            setError('Kunci Universal tidak boleh kosong!');
            return;
        }
        setIsLoading(true);
        setError('');
        setOutput(null);
        
        const formData = new FormData();
        formData.append('key', universalKey);
        
        try {
            const response = await fetch('http://127.0.0.1:5000/api/decrypt', {
                method: 'POST',
                body: formData,
            });
            const result = await response.json();
            if (!response.ok && result.error) throw new Error(result.error);
            
            setOutput(result);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };
    
    // --- PENAMBAHAN FUNGSI UNTUK MENGUNDUH GAMBAR ---
    const handleDownload = () => {
        if (!output || !output.stegoImageB64) return;
        
        // Membuat elemen link sementara
        const link = document.createElement('a');
        link.href = output.stegoImageB64;
        link.download = 'gambar_hasil_dekripsi.png';
        
        // Menambahkan link ke body, mengkliknya, lalu menghapusnya
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    return (
        <div className="space-y-6">
            {error && <Alert message={error} type="error" onDismiss={() => setError('')} />}
            <div className="space-y-4">
                <div className="flex items-center gap-2 mb-2"><KeyRound className="h-5 w-5 text-purple-600" /><label htmlFor="key-input" className="text-sm font-semibold text-slate-700">Kunci Universal</label></div>
                <textarea id="key-input" rows="8" value={universalKey} onChange={(e) => setUniversalKey(e.target.value)} className="w-full p-4 border border-slate-200 rounded-xl font-mono text-xs" placeholder="Tempelkan Kunci Universal yang Anda terima di sini..."/>
            </div>
            
            <button onClick={handleDecrypt} disabled={isLoading || !universalKey} className="w-full bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-bold py-4 px-6 rounded-xl flex items-center justify-center gap-3 shadow-lg disabled:opacity-50">
                {isLoading ? <><Loader2 className="animate-spin h-5 w-5" />Memproses...</> : <><Unlock className="h-5 w-5" />Buka & Verifikasi Pesan</>}
            </button>
            
            {output && (
                <div className="mt-8 pt-6 border-t grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Kolom Hasil Kiri (Status & Pesan) */}
                    <div className="space-y-4">
                        <div className={`p-4 rounded-xl border flex items-center gap-3 shadow-sm ${output.isValid ? 'bg-green-100 border-green-200 text-green-800' : 'bg-red-100 border-red-200 text-red-800'}`}>
                            {output.isValid ? <CheckCircle className="h-6 w-6" /> : <AlertTriangle className="h-6 w-6" />}
                            <h3 className="font-bold text-lg">Status: {output.isValid ? 'ASLI & VALID' : 'TIDAK VALID / KORUP'}</h3>
                        </div>
                        <div>
                            <label className="block text-sm font-semibold mb-2">Pesan Diterima:</label>
                            <div className="w-full p-4 bg-slate-50 border rounded-xl min-h-[100px]">{output.message}</div>
                        </div>
                    </div>
                    {/* Kolom Hasil Kanan (Gambar) */}
                    <div className="space-y-4">
                        {/* --- PENAMBAHAN TOMBOL UNDUH DI SINI --- */}
                        <div className="flex items-center justify-between">
                            <label className="block text-sm font-semibold">Gambar yang Disisipi:</label>
                            {output.stegoImageB64 && (
                                <button onClick={handleDownload} className="flex items-center gap-2 text-sm bg-green-100 text-green-700 px-3 py-1 rounded-lg hover:bg-green-200 transition-colors">
                                    <Download size={14} />
                                    Unduh
                                </button>
                            )}
                        </div>
                        {output.stegoImageB64 ? 
                            <img src={output.stegoImageB64} className="rounded-xl border-2 w-full object-cover" alt="Gambar Hasil"/>
                            : <div className="w-full p-4 bg-slate-100 border rounded-xl text-center text-slate-500">Gambar tidak tersedia.</div>
                        }
                    </div>
                </div>
            )}
        </div>
    );
};


export default function App() {
    const [activeTab, setActiveTab] = useState('sender');
    const [showFeatures, setShowFeatures] = useState(false);
    const [universalKey, setUniversalKey] = useState('');

    const handleNewKey = (key) => {
        setUniversalKey(key);
        setActiveTab('receiver');
    };

    return (
        <div className="bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 min-h-screen font-sans text-slate-800">
            <div className="container mx-auto p-4 md:p-8 max-w-5xl">
                <header className="text-center mb-8">
                    <div className="flex items-center justify-center gap-3 mb-4"><div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl shadow-lg"><Shield className="h-8 w-8 text-white" /></div><h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">CryptoStego Pro</h1></div>
                    <p className="text-slate-600 text-lg max-w-2xl mx-auto">Solusi keamanan digital modern dengan kriptografi hibrida dan steganografi canggih</p>
                    <button onClick={() => setShowFeatures(!showFeatures)} className="mt-4 inline-flex items-center gap-2 text-sm text-slate-600 hover:text-blue-600"><Sparkles className="h-4 w-4" />Fitur Unggulan{showFeatures ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}</button>
                    {showFeatures && <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"><FeatureCard icon={Lock} title="Enkripsi Hibrida" description="AES-128 & RSA-2048" color="blue" /><FeatureCard icon={ImageIcon} title="Steganografi LSB" description="Sembunyikan data dalam gambar" color="green" /><FeatureCard icon={Shield} title="Tanda Tangan Digital" description="Schnorr Signature" color="purple" /><FeatureCard icon={Zap} title="Performa Cepat" description="Python Backend (Flask)" color="amber" /></div>}
                </header>
                <div className="bg-white/70 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 p-6">
                    <div className="mb-6 border-b border-slate-200"><nav className="flex space-x-1"><TabButton id="sender" activeTab={activeTab} setActiveTab={setActiveTab} icon={<Send size={18} />} label="Pengirim" color="blue" /><TabButton id="receiver" activeTab={activeTab} setActiveTab={setActiveTab} icon={<Mail size={18} />} label="Penerima" color="purple" /></nav></div>
                    {activeTab === 'sender' && <SenderPanel onNewKeyGenerated={handleNewKey} />}
                    {activeTab === 'receiver' && <ReceiverPanel universalKey={universalKey} setUniversalKey={setUniversalKey} />}
                </div>
            </div>
        </div>
    );
}
