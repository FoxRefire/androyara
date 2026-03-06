package com.example.yaraxsample

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.yaraxsample.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Default sample YARA rule
        binding.rulesEdit.setText(DEFAULT_RULES)

        binding.scanButton.setOnClickListener { runScan() }
    }

    private fun runScan() {
        val rulesSrc = binding.rulesEdit.text.toString()
        if (rulesSrc.isBlank()) {
            Toast.makeText(this, "Enter YARA rules", Toast.LENGTH_SHORT).show()
            return
        }

        val inputText = binding.inputEdit.text.toString()
        if (inputText.isBlank()) {
            Toast.makeText(this, "Enter text to scan", Toast.LENGTH_SHORT).show()
            return
        }

        binding.progressBar.visibility = View.VISIBLE
        binding.resultsList.adapter = null

        try {
            val rules = YaraX.compile(rulesSrc)
            try {
                val scanner = rules.createScanner()
                try {
                    val matches = scanner.scanString(inputText)
                    showResults(matches)
                    if (matches.isEmpty()) {
                        Toast.makeText(this, "No matches", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this, "Found ${matches.size} match(es)", Toast.LENGTH_SHORT).show()
                    }
                } finally {
                    scanner.close()
                }
            } finally {
                rules.close()
            }
        } catch (e: YaraException) {
            showResults(emptyList())
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        } finally {
            binding.progressBar.visibility = View.GONE
        }
    }

    private fun showResults(matches: List<String>) {
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_list_item_1,
            matches.ifEmpty { listOf("(no matches)") }
        )
        binding.resultsList.adapter = adapter
    }

    companion object {
        private val DEFAULT_RULES = """
            rule example_string {
                strings:
                    ${'$'}hello = "Hello"
                    ${'$'}world = "World"
                    ${'$'}malicious = "malware"
                condition:
                    any of them
            }
            
            rule example_hex {
                strings:
                    ${'$'}hex = { 48 65 6c 6c 6f }
                condition:
                    ${'$'}hex
            }
        """.trimIndent()
    }
}
