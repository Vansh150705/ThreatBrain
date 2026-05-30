import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import { Toaster, toast } from "sonner";

function App() {
  return (
    <div className="min-h-screen bg-slate-50 p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary-600 flex items-center justify-center text-white font-bold">
            T
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900">
              ThreatBrain — Component Library
            </h1>
            <p className="text-sm text-slate-500">step 5.3 ✓ shadcn/ui ready</p>
          </div>
        </div>

        {/* Buttons card */}
        <Card>
          <CardHeader>
            <CardTitle>Buttons</CardTitle>
            <CardDescription>All shadcn button variants.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-3">
            <Button>Default</Button>
            <Button variant="secondary">Secondary</Button>
            <Button variant="outline">Outline</Button>
            <Button variant="ghost">Ghost</Button>
            <Button variant="destructive">Destructive</Button>
            <Button variant="link">Link</Button>
            <Button disabled>Disabled</Button>
          </CardContent>
        </Card>

        {/* Inputs card */}
        <Card>
          <CardHeader>
            <CardTitle>Form fields</CardTitle>
            <CardDescription>Inputs, labels, and form layout.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 max-w-md">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="jane@acme.example" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" placeholder="••••••••" />
            </div>
            <Button className="w-full">Sign in</Button>
          </CardContent>
        </Card>

        {/* Badges card */}
        <Card>
          <CardHeader>
            <CardTitle>Severity badges</CardTitle>
            <CardDescription>
              Status indicators for threats and incidents.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Badge variant="default">Default</Badge>
            <Badge variant="secondary">Secondary</Badge>
            <Badge variant="outline">Outline</Badge>
            <Badge variant="destructive">Destructive</Badge>
            <Separator orientation="vertical" className="h-6 mx-2" />
            <Badge className="bg-severity-info text-white">info</Badge>
            <Badge className="bg-severity-low text-white">low</Badge>
            <Badge className="bg-severity-medium text-white">medium</Badge>
            <Badge className="bg-severity-high text-white">high</Badge>
            <Badge className="bg-severity-critical text-white">critical</Badge>
          </CardContent>
        </Card>

        {/* Avatars + Toast card */}
        <Card>
          <CardHeader>
            <CardTitle>Avatars + Toast</CardTitle>
            <CardDescription>User identity and notifications.</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <Avatar>
              <AvatarFallback className="bg-primary-600 text-white">
                JM
              </AvatarFallback>
            </Avatar>
            <Avatar>
              <AvatarFallback className="bg-severity-medium text-white">
                MC
              </AvatarFallback>
            </Avatar>
            <Avatar>
              <AvatarFallback className="bg-severity-critical text-white">
                PS
              </AvatarFallback>
            </Avatar>
            <Separator orientation="vertical" className="h-10" />
            <Button
              variant="outline"
              onClick={() =>
                toast.success("Threat classified", {
                  description: "Severity: high · Confidence: 92",
                })
              }
            >
              Trigger toast
            </Button>
          </CardContent>
        </Card>
      </div>

      <Toaster richColors position="top-right" />
    </div>
  );
}

export default App;