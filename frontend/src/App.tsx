import { motion } from "motion/react";
import {
  Shield,
  Brain,
  AlertTriangle,
  Activity,
  Zap,
  Search,
  Eye,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// The 7 agents — what we built in Phase 4
const agents = [
  {
    key: "triage",
    name: "Triage",
    icon: AlertTriangle,
    description: "First-responder classification with MITRE mapping",
    color: "bg-severity-high",
    runs: 47,
  },
  {
    key: "threat-intel",
    name: "Threat Intel",
    icon: Search,
    description: "Live AbuseIPDB enrichment + IOC caching",
    color: "bg-severity-info",
    runs: 31,
  },
  {
    key: "investigation",
    name: "Investigation",
    icon: Brain,
    description: "Correlates threats into attack stories",
    color: "bg-primary-600",
    runs: 12,
  },
  {
    key: "response",
    name: "Response",
    icon: Zap,
    description: "Playbook execution with audit trail",
    color: "bg-severity-critical",
    runs: 24,
  },
  {
    key: "forensics",
    name: "Forensics",
    icon: Eye,
    description: "Chain-of-custody timeline reconstruction",
    color: "bg-severity-medium",
    runs: 8,
  },
  {
    key: "compliance",
    name: "Compliance",
    icon: CheckCircle2,
    description: "GDPR / HIPAA / PCI-DSS reporting",
    color: "bg-severity-low",
    runs: 6,
  },
  {
    key: "hunt",
    name: "Hunt",
    icon: Activity,
    description: "Proactive hypothesis generation",
    color: "bg-primary-500",
    runs: 14,
  },
];

// Entrance animation for the whole list
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.2,
    },
  },
};

// Each card slides up + fades in
const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      type: "spring" as const,
      damping: 16,
      stiffness: 200,
    },
  },
};

function App() {
  return (
    <div className="min-h-screen bg-slate-50">
      {/* Hero section */}
      <div className="max-w-6xl mx-auto px-8 pt-16 pb-8">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-4 mb-2"
        >
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-slate-900 tracking-tight">
              ThreatBrain
            </h1>
            <p className="text-sm text-slate-500">
              The Neural SOC · 7 specialized AI agents
            </p>
          </div>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.15 }}
          className="text-slate-600 text-lg leading-relaxed max-w-2xl mt-6"
        >
          Step 5.4 ✓ Framer Motion + Lucide icons wired up. Watch the agent
          cards stagger in below.
        </motion.p>
      </div>

      {/* Agent grid */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="max-w-6xl mx-auto px-8 pb-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5"
      >
        {agents.map((agent) => {
          const Icon = agent.icon;
          return (
            <motion.div
              key={agent.key}
              variants={itemVariants}
              whileHover={{ y: -4, transition: { duration: 0.15 } }}
            >
              <Card className="cursor-pointer transition-shadow hover:shadow-lg h-full">
                <CardContent className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div
                      className={`${agent.color} w-11 h-11 rounded-lg flex items-center justify-center shadow-sm`}
                    >
                      <Icon className="w-5 h-5 text-white" strokeWidth={2} />
                    </div>
                    <Badge variant="outline" className="font-mono text-xs">
                      {agent.runs} runs
                    </Badge>
                  </div>
                  <h3 className="font-semibold text-slate-900 mb-1">
                    {agent.name}
                  </h3>
                  <p className="text-sm text-slate-500 leading-relaxed">
                    {agent.description}
                  </p>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </motion.div>

      {/* CTA section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.9 }}
        className="max-w-6xl mx-auto px-8 pb-16 text-center"
      >
        <Button size="lg" className="gap-2">
          <Zap className="w-4 h-4" />
          Run full pipeline
        </Button>
        <p className="text-xs text-slate-400 mt-4 font-mono">
          step 5.4 ✓ motion + lucide
        </p>
      </motion.div>
    </div>
  );
}

export default App;