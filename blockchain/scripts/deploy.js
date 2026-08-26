import hre from "hardhat";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  console.log("Deploying ForecastRegistry...");
  const ForecastRegistry = await hre.ethers.getContractFactory("ForecastRegistry");
  const registry = await ForecastRegistry.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  console.log(`ForecastRegistry deployed to: ${address}`);

  const deploymentDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentDir)) {
    fs.mkdirSync(deploymentDir);
  }
  
  // Get ABI from Hardhat artifacts
  const artifactPath = path.join(__dirname, "../artifacts/contracts/ForecastRegistry.sol/ForecastRegistry.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  
  const deploymentData = {
    address: address,
    abi: artifact.abi
  };
  
  fs.writeFileSync(
    path.join(deploymentDir, "localhost.json"),
    JSON.stringify(deploymentData, null, 2)
  );
  console.log(`Deployment details saved to deployments/localhost.json`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
