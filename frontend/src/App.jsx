import Dashboard from '@/pages/Dashboard'
import Navbar from '@/components/layout/Navbar'

function App() {
    return (
        <div className="min-h-screen bg-background text-foreground">
            <Navbar />
            <main className="container mx-auto px-4 py-8">
                <Dashboard />
            </main>
        </div>
    )
}

export default App
